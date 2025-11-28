from flask import Flask, render_template, request, send_from_directory, Response, jsonify, g
from cryptography.hazmat.primitives.serialization import pkcs12, BestAvailableEncryption
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.x509.oid import NameOID
from lxml import etree
from xhtml2pdf import pisa
from flask import redirect, url_for, send_file
import qrcode
import sqlite3
import base64
import uuid
import os
import io
import re
from datetime import datetime, timedelta, timezone

app = Flask(__name__)

# Cấu hình Database & Thư mục
DATABASE = 'invoices.db'
os.makedirs("signed_invoices", exist_ok=True)
os.makedirs("generated_pfx", exist_ok=True) # Thư mục cho PFX Generator

# ============================================
# 0. PFX GENERATOR CORE LOGIC
# ============================================
def generate_pfx_core(pfx_password, common_name, org_name, country_code):
    """Tạo dữ liệu PFX và các khóa PEM, KHÔNG lưu file."""
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )

    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, country_code),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, org_name),
        x509.NameAttribute(NameOID.COMMON_NAME, common_name),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "State"),
        x509.NameAttribute(NameOID.LOCALITY_NAME, "City"),
    ])

    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.utcnow())
        .not_valid_after(datetime.utcnow() + timedelta(days=365))  # 1 năm
        .sign(private_key, hashes.SHA256())
    )

    pfx_data = pkcs12.serialize_key_and_certificates(
        name=common_name.encode(),
        key=private_key,
        cert=cert,
        cas=None,
        encryption_algorithm=BestAvailableEncryption(
            pfx_password.encode()
        ),
    )
        
    private_key_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    ).decode('utf-8')

    cert_pem = cert.public_bytes(serialization.Encoding.PEM).decode('utf-8')

    return {
        "pfx_data": base64.b64encode(pfx_data).decode(), # Base64 PFX byte array
        "pfx_password": pfx_password,
        "cn": common_name,
        "org": org_name,
        "valid_to": cert.not_valid_after_utc.strftime('%Y-%m-%d %H:%M:%S'),
        "private_key_pem": private_key_pem,
        "cert_pem": cert_pem
    }

# ============================================
# 1. DATABASE UTILITIES
# ============================================
def get_db():
    db = getattr(g, '_database', None)
    if db is None:
        db = g._database = sqlite3.connect(DATABASE)
        db.row_factory = sqlite3.Row 
    return db

@app.teardown_appcontext
def close_connection(exception):
    db = getattr(g, '_database', None)
    if db is not None:
        db.close()

def init_db():
    with app.app_context():
        db = get_db()
        db.execute("""
            CREATE TABLE IF NOT EXISTS INVOICES (
                id TEXT PRIMARY KEY,
                status TEXT NOT NULL,
                message TEXT,
                path TEXT NOT NULL,
                common_name TEXT,
                valid_to TEXT,
                verification_status TEXT DEFAULT 'PENDING', 
                created_at TIMESTAMP DEFAULT (datetime('now', '+7 hours'))
            );
        """)
        db.commit()

# ============================================
# 2. CORE CRYPTO & XML UTILITIES
# ============================================
def canonicalize_xml_string(xml_bytes):
    xml_text = xml_bytes.decode('utf-8').strip()
    xml_text = re.sub(r'<\?xml[^?]+\?>', '', xml_text, 1, flags=re.IGNORECASE).strip()
    xml_text = xml_text.replace('\n', '').replace('\r', '').replace('\t', '')
    xml_text = re.sub(r'>\s+<', '><', xml_text).strip()
    return xml_text.encode('utf-8')

def sign_xml(xml_bytes, pfx_bytes, password):
    # ... (Hàm ký giữ nguyên) ...
    private_key, cert, _ = pkcs12.load_key_and_certificates(pfx_bytes, password.encode())
    signed_data = canonicalize_xml_string(xml_bytes) 
    digest = hashes.Hash(hashes.SHA256())
    digest.update(signed_data)
    hashed = digest.finalize()
    signature = private_key.sign(hashed, padding.PKCS1v15(), hashes.SHA256())
    signature_b64 = base64.b64encode(signature).decode()
    cert_der = cert.public_bytes(serialization.Encoding.DER)
    cert_b64 = base64.b64encode(cert_der).decode()
    xml_text = xml_bytes.decode("utf-8")
    signature_block = (
        "<Signature>"
        f"<SignatureValue>{signature_b64}</SignatureValue>"
        f"<X509Certificate>{cert_b64}</X509Certificate>"
        "</Signature>"
    )
    pos = xml_text.rfind("</Invoice>")
    signed_text = xml_text[:pos] + "\n" + signature_block + "\n" + xml_text[pos:]
    return signed_text.encode("utf-8")

def get_hash_sig_pk(xml_bytes):
    xml_text = xml_bytes.decode("utf-8")
    start = xml_text.find("<Signature>")
    end = xml_text.find("</Signature>") + len("</Signature>")
    if start == -1 or end == -1:
        return False, "❌ Không tìm thấy chữ ký", None
    sig_block = xml_text[start:end]
    try:
        sig_val = re.search(r"<SignatureValue>(.*?)</SignatureValue>", sig_block, re.DOTALL).group(1).strip()
        cert_val = re.search(r"<X509Certificate>(.*?)</X509Certificate>", sig_block, re.DOTALL).group(1).strip()
    except AttributeError:
        return False, "❌ Cấu trúc <Signature> không hợp lệ", None
    signature = base64.b64decode(sig_val)
    try:
        cert = x509.load_der_x509_certificate(base64.b64decode(cert_val))
        pubkey = cert.public_key()
    except Exception as e:
        return False, f"❌ Lỗi tải chứng chỉ: {e}", None
    unsigned_xml_text = xml_text.replace(sig_block, "")
    unsigned_xml_bytes = unsigned_xml_text.encode("utf-8")
    unsigned_xml_canonical = canonicalize_xml_string(unsigned_xml_bytes)
    digest = hashes.Hash(hashes.SHA256())
    digest.update(unsigned_xml_canonical)
    hashed = digest.finalize().hex()

    return hashed, sig_val, cert_val 

def verify_xml(xml_bytes):
    # ... (Logic xác minh và khắc phục lỗi DeprecationWarning) ...
    xml_text = xml_bytes.decode("utf-8")
    start = xml_text.find("<Signature>")
    end = xml_text.find("</Signature>") + len("</Signature>")
    if start == -1 or end == -1:
        return False, "❌ Không tìm thấy chữ ký", None
    sig_block = xml_text[start:end]
    try:
        sig_val = re.search(r"<SignatureValue>(.*?)</SignatureValue>", sig_block, re.DOTALL).group(1).strip()
        cert_val = re.search(r"<X509Certificate>(.*?)</X509Certificate>", sig_block, re.DOTALL).group(1).strip()
    except AttributeError:
        return False, "❌ Cấu trúc <Signature> không hợp lệ", None
    signature = base64.b64decode(sig_val)
    try:
        cert = x509.load_der_x509_certificate(base64.b64decode(cert_val))
        pubkey = cert.public_key()
    except Exception as e:
        return False, f"❌ Lỗi tải chứng chỉ: {e}", None
    unsigned_xml_text = xml_text.replace(sig_block, "")
    unsigned_xml_bytes = unsigned_xml_text.encode("utf-8")
    unsigned_xml_canonical = canonicalize_xml_string(unsigned_xml_bytes)
    digest = hashes.Hash(hashes.SHA256())
    digest.update(unsigned_xml_canonical)
    hashed = digest.finalize()
    
    # Khắc phục cảnh báo DeprecationWarning: Sử dụng _utc
    now = datetime.now(timezone.utc)
    valid_to = cert.not_valid_after_utc.strftime('%Y-%m-%d %H:%M:%S') 
    
    cert_info = {
        "common_name": cert.subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)[0].value,
        "valid_to": valid_to,
        "organization": cert.subject.get_attributes_for_oid(x509.NameOID.ORGANIZATION_NAME)[0].value,
        "country": cert.subject.get_attributes_for_oid(x509.NameOID.COUNTRY_NAME)[0].value,
        "valid_from": cert.not_valid_before_utc.strftime('%Y-%m-%d %H:%M:%S'),
        "verification_checks": []
    }
    
    # KIỂM TRA TỪNG ĐIỀU KIỆN RIÊNG BIỆT
    all_valid = True
    valid_count = 0
    total_checks = 3
    
    # Kiểm tra 1: Certificate Validity & Organization Match (Chứng thư hợp lệ + Tổ chức khớp)
    cert_expired = now > cert.not_valid_after_utc
    if cert_expired:
        cert_info["verification_checks"].append({
            "status": "invalid",
            "message": f"Chứng thư ĐÃ HẾT HẠN vào {valid_to}. Xác thực tổ chức THẤT BẠI."
        })
        all_valid = False
    else:
        cert_info["verification_checks"].append({
            "status": "valid",
            "message": f"Chứng thư hợp lệ, tổ chức khớp: {cert_info['organization']}"
        })
        valid_count += 1
    
    # Kiểm tra 2: Data Integrity (Message & Digest) - LUÔN KIỂM TRA
    digest_check = {
        "status": "checking",
        "message": "Nội dung & mã băm giống hệt nhau. Tính toàn vẹn dữ liệu được xác nhận."
    }
    
    # Kiểm tra 3: Signature Validity - LUÔN KIỂM TRA
    signature_check = {
        "status": "checking",
        "message": "Chữ ký HỢP LỆ. Nguồn gốc và tính toàn vẹn dữ liệu được xác nhận."
    }
    
    try:
        pubkey.verify(signature, hashed, padding.PKCS1v15(), hashes.SHA256())
        # Nếu verify thành công
        digest_check["status"] = "valid"
        signature_check["status"] = "valid"
        cert_info["verification_checks"].append(digest_check)
        cert_info["verification_checks"].append(signature_check)
        valid_count += 2
    except InvalidSignature:
        digest_check["status"] = "invalid"
        digest_check["message"] = "Nội dung & mã băm KHÔNG giống nhau. Tính toàn vẹn dữ liệu BỊ PHÁ VỠ."
        signature_check["status"] = "invalid"
        signature_check["message"] = "Chữ ký KHÔNG HỢP LỆ. Xác thực THẤT BẠI."
        cert_info["verification_checks"].append(digest_check)
        cert_info["verification_checks"].append(signature_check)
        all_valid = False
    
    # Thêm thông báo tổng kết
    cert_info["verification_summary"] = f"Đã kiểm tra {total_checks} điều kiện: {valid_count} hợp lệ ✓, {total_checks - valid_count} không hợp lệ ✗"
    
    # Kết luận cuối cùng
    if not all_valid:
        if cert_expired:
            return False, "❌ Chứng chỉ đã hết hạn - Xác thực thất bại", cert_info
        else:
            return False, "❌ Chữ ký không hợp lệ - Xác thực thất bại", cert_info
    
    return True, "✅ Chữ ký hợp lệ và Chứng chỉ còn hiệu lực", cert_info

def update_verification_status(invoice_id, new_status):
    with app.app_context():
        db = get_db()
        db.execute("""
            UPDATE INVOICES SET verification_status = ? WHERE id = ?
        """, (new_status, invoice_id))
        db.commit()

def convert_html_to_pdf(html_content):
    pdf_buffer = io.BytesIO()
    pisa_status = pisa.CreatePDF(
        html_content,
        dest=pdf_buffer    
    )
    if pisa_status.err:
        return None
    
    pdf_buffer.seek(0)
    return pdf_buffer

# ============================================
# 3. APPLICATION ROUTES
# ============================================
@app.route("/")
def index():
    return render_template("index.html")

@app.route("/sign-invoice")
def sign_invoice():
    """Trang ký số hóa đơn (form)."""
    return render_template("sign_invoice.html")


# --- PFX GENERATOR ROUTES ---
@app.route("/generator")
def generator_form():
    return render_template("pfx_generator.html")

@app.route("/generate_pfx_route", methods=["POST"])
def generate_pfx_route():
    cn = request.form.get("common_name", "demo.vn")
    org = request.form.get("organization", "Demo Tech Co.")
    country = request.form.get("country", "VN")
    password = request.form.get("password", "123456")

    try:
        # Gọi hàm tạo dữ liệu
        data = generate_pfx_core(password, cn, org, country)
        data["status"] = "success"
        return jsonify(data)
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 400
    
@app.route("/download_pfx", methods=["POST"])
def download_pfx():
    pfx_b64 = request.form.get('pfx_data')
    filename = request.form.get('filename')
    
    if not pfx_b64 or not filename:
        return "Missing data", 400

    try:
        pfx_bytes = base64.b64decode(pfx_b64)
    except:
        return "Invalid Base64 data", 400

    response = Response(
        pfx_bytes,
        mimetype='application/x-pkcs12',
        headers={
            "Content-Disposition": f"attachment; filename={filename}.pfx",
            "Content-Length": len(pfx_bytes)
        }
    )
    return response
# --- END PFX GENERATOR ROUTES ---


@app.route("/preview_sign", methods=["POST"])
def preview_sign():
    xml_file = request.files.get("xml_file")
    pfx_file = request.files.get("pfx_file")
    password = request.form.get("password")

    if not xml_file or not pfx_file or not password:
        return jsonify({"status": "error", "message": "Thiếu file hoặc mật khẩu."}), 400

    try:
        xml_bytes = xml_file.read()
        pfx_bytes = pfx_file.read()

        private_key, cert, _ = pkcs12.load_key_and_certificates(
            pfx_bytes, password.encode()
        )
        
        cert_info = {
            "common_name": cert.subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)[0].value,
            "organization": cert.subject.get_attributes_for_oid(x509.NameOID.ORGANIZATION_NAME)[0].value,
            "valid_to": cert.not_valid_after_utc.strftime('%Y-%m-%d %H:%M:%S'),
        }

        xml_tree = etree.fromstring(xml_bytes)
        invoice_info = {
            "number": xml_tree.findtext("InvoiceNumber"),
            "date": xml_tree.findtext("IssueDate"),
            "total": xml_tree.findtext("TotalAmount")
        }

        private_key_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ).decode('utf-8')

        public_key_pem = cert.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ).decode('utf-8')


        return jsonify({
            "status": "success",
            "cert": cert_info,
            "invoice": invoice_info,
            "privatekey": private_key_pem,
            "pubkey": public_key_pem
        })

    except InvalidSignature:
        return jsonify({"status": "error", "message": "Mật khẩu PFX không đúng hoặc file PFX hỏng."}), 400
    except Exception as e:
        return jsonify({"status": "error", "message": f"Lỗi xử lý file: {str(e)}"}), 500

@app.route("/sign", methods=["POST"])
def sign_route():
    xml_file = request.files["xml_file"]
    pfx_file = request.files["pfx_file"]
    password = request.form["password"]

    xml_bytes = xml_file.read()
    pfx_bytes = pfx_file.read()

    signed_xml = sign_xml(xml_bytes, pfx_bytes, password)

    invoice_id = str(uuid.uuid4())
    path = os.path.join("signed_invoices", f"{invoice_id}.xml")

    with open(path, "wb") as f:
        f.write(signed_xml)

    # Auto-verify
    ok, msg, cert_info = False, None, None
    try:
        ok, msg, cert_info = verify_xml(signed_xml)
    except Exception as e:
        ok = False
        msg = f"❌ Ký số thất bại: Lỗi xác minh nội bộ ({type(e).__name__})"
        cert_info = {}


    initial_message = "⚠️ Đang chờ xác thực"
    initial_status = "valid"


    # Ghi vào SQLite
    db = get_db()
    db.execute("""
        INSERT INTO INVOICES (id, status, message, path, common_name, valid_to, verification_status)
        VALUES (?, ?, ?, ?, ?, ?, ?)
    """, (invoice_id, initial_status, initial_message, path, cert_info.get("common_name"), cert_info.get("valid_to"), 'PENDING'))
    db.commit()

    # Chuyển hướng đến danh sách hóa đơn
    return redirect(url_for('list_invoices'))

@app.route("/invoices")
def list_invoices():
    db = get_db()
    invoices_data = db.execute("SELECT * FROM INVOICES ORDER BY created_at DESC").fetchall()
    invoices = {row['id']: dict(row) for row in invoices_data}
    return render_template("invoices.html", invoices=invoices)

@app.route("/invoice/<id>")
def invoice_detail(id):
    db = get_db()
    invoice_row = db.execute("SELECT * FROM INVOICES WHERE id = ?", (id,)).fetchone()
    
    if not invoice_row:
        return "Invoice not found", 404
        
    invoice = dict(invoice_row)

    hashed, sig, cert = get_hash_sig_pk(open(invoice['path'], 'rb').read())
    # Chạy xác thực lại để lấy đầy đủ thông tin chi tiết (organization, country, valid_from)
    try:
        with open(invoice['path'], 'rb') as f:
            signed_xml = f.read()
        _, _, full_cert_info = verify_xml(signed_xml)
        invoice.update(full_cert_info) # Cập nhật các trường cert chi tiết
        
    except Exception as e:
        invoice["organization"] = "N/A"
        invoice["country"] = "N/A"
        invoice["valid_from"] = "N/A"

    return render_template("invoice_detail.html", id=id, invoice=invoice, signature=sig, hashed=hashed, cert=cert)

@app.route('/download_pdf/<id>')
def download_pdf(id):
    db = get_db()
    invoice_row = db.execute("SELECT * FROM INVOICES WHERE id = ?", (id,)).fetchone()
    
    if not invoice_row:
        return "Invoice not found", 404
    
    invoice = dict(invoice_row)
    
    try:
        with open(invoice['path'], 'rb') as f:
            signed_xml_bytes = f.read()
            xml_tree = etree.fromstring(signed_xml_bytes)
            # Xóa block <Signature> để hiển thị nội dung XML trong PDF nếu cần
            sig_element = xml_tree.find("Signature")
            if sig_element is not None:
                xml_tree.remove(sig_element)
    except Exception as e:
        return f"Lỗi đọc file XML: {e}", 500

    try:
        # Lấy signature và chứng chỉ từ XML
        hashed, sig_val, cert_b64 = get_hash_sig_pk(signed_xml_bytes)

        # Nếu get_hash_sig_pk trả về lỗi (hashed == False) thì đặt giá trị mặc định
        if hashed is False:
            sig_val = sig_val or "N/A"
            public_key_pem = "N/A"
        else:
            public_key_pem = "N/A"
            if cert_b64 and isinstance(cert_b64, str):
                try:
                    cert_obj = x509.load_der_x509_certificate(base64.b64decode(cert_b64))
                    public_key_pem = cert_obj.public_key().public_bytes(
                        serialization.Encoding.PEM,
                        serialization.PublicFormat.SubjectPublicKeyInfo
                    ).decode('utf-8')
                except Exception:
                    public_key_pem = "N/A"

        # Tạo payload cho QR (SignatureValue + PublicKey)
        qr_payload = f"SignatureValue:\n{sig_val}\n\nPublicKey:\n{public_key_pem}"

        # Tạo ảnh QR (yêu cầu qrcode + pillow đã cài)
        try:
            qr = qrcode.QRCode(box_size=4, border=2)
            qr.add_data(qr_payload)
            qr.make(fit=True)
            img = qr.make_image(fill_color="black", back_color="white")
            qr_buf = io.BytesIO()
            img.save(qr_buf, format="PNG")
            qr_buf.seek(0)
            qr_b64 = base64.b64encode(qr_buf.read()).decode('utf-8')
            qr_data_uri = f"data:image/png;base64,{qr_b64}"
        except Exception as e:
            return f"Lỗi tạo QR: {e}. Hãy cài qrcode và pillow: pip install qrcode[pil]", 500

        # Render HTML với qr_data_uri (phải render sau khi tạo QR)
        html_content = render_template(
            'invoice_pdf.html', 
            invoice=invoice, 
            xml_tree=xml_tree,
            qr_data_uri=qr_data_uri
        )

        # Tạo PDF
        pdf_buffer = convert_html_to_pdf(html_content)
        if pdf_buffer is None:
            return "Lỗi tạo PDF: Kiểm tra cú pháp HTML/CSS trong invoice_pdf.html", 500

    except Exception as e:
        return f"Lỗi xử lý tạo PDF: {e}", 500
        
    return send_file(
        path_or_file=pdf_buffer,
        mimetype='application/pdf',
        as_attachment=True,
        download_name=f"invoice_{id}.pdf"
    )

@app.route("/verification")
def list_verification():
    db = get_db()
    # Lấy tất cả hóa đơn, sắp xếp theo trạng thái chưa xác thực lên đầu
    invoices_data = db.execute("""
        SELECT * FROM INVOICES 
        ORDER BY 
            CASE WHEN verification_status = 'PENDING' THEN 0 ELSE 1 END, 
            created_at DESC
    """).fetchall()
    
    invoices = {row['id']: dict(row) for row in invoices_data}
    return render_template("verification_list.html", invoices=invoices) # Dùng template mới

@app.route("/confirm_verify/<id>", methods=["POST"])
def confirm_verify(id):
    db = get_db()
    invoice_row = db.execute("SELECT * FROM INVOICES WHERE id = ?", (id,)).fetchone()
    
    if not invoice_row:
        return jsonify({"status": "error", "message": "Không tìm thấy hóa đơn"}), 404
    
    invoice = dict(invoice_row)
    
    with open(invoice['path'], 'rb') as f:
        signed_xml = f.read()
    ok, msg, full_cert_info = verify_xml(signed_xml)

    if ok:
        new_status = 'VERIFIED'
    else:
        new_status = 'REJECTED'
    
    # Cập nhật vào SQLite
    db.execute("""
        UPDATE INVOICES SET verification_status = ?, message = ? WHERE id = ?
    """, (new_status, msg, id))
    db.commit()
    
    # Lấy public key từ certificate để hiển thị
    public_key_pem = "N/A"
    try:
        xml_text = signed_xml.decode("utf-8")
        cert_match = re.search(r"<X509Certificate>(.*?)</X509Certificate>", xml_text, re.DOTALL)
        if cert_match:
            cert_b64 = cert_match.group(1).strip()
            cert = x509.load_der_x509_certificate(base64.b64decode(cert_b64))
            public_key_pem = cert.public_key().public_bytes(
                serialization.Encoding.PEM,
                serialization.PublicFormat.SubjectPublicKeyInfo
            ).decode('utf-8')
    except Exception:
        pass
    
    # Trả về JSON với thông tin xác thực chi tiết
    return jsonify({
        "status": "success",
        "verification_result": ok,
        "message": msg,
        "verification_checks": full_cert_info.get("verification_checks", []),
        "verification_summary": full_cert_info.get("verification_summary", ""),
        "public_key": public_key_pem
    })

@app.route("/api/invoice_detail/<id>")
def api_invoice_detail(id):
    db = get_db()
    invoice_row = db.execute("SELECT * FROM INVOICES WHERE id = ?", (id,)).fetchone()
    
    if not invoice_row:
        return jsonify({"error": "Invoice not found"}), 404
        
    invoice = dict(invoice_row)
    
    # Chạy xác thực lại để lấy thông tin cert đầy đủ
    try:
        with open(invoice['path'], 'rb') as f:
            signed_xml = f.read()
        # Chú ý: Cần đảm bảo hàm verify_xml đã được sửa lỗi DeprecationWarning
        is_valid, msg, full_cert_info = verify_xml(signed_xml) 
        invoice.update(full_cert_info) 
        invoice['current_verification_result'] = is_valid
        invoice['current_verification_message'] = msg
    except Exception as e:
        invoice["organization"] = "N/A"
        invoice["country"] = "N/A"
        invoice["valid_from"] = "N/A"
        invoice["verification_checks"] = []
        invoice['current_verification_result'] = False
        invoice['current_verification_message'] = f"Lỗi xác thực: {str(e)}"
        
    invoice['verification_status'] = invoice.get('verification_status', 'N/A')
    invoice['verification_message'] = invoice.get('verification_message', 'Chưa có thông báo xử lý.')
        
    return jsonify({
        "status": "success",
        "invoice": invoice
    })
if __name__ == "__main__":
    init_db() 
    app.run(debug=True)