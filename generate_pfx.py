from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.serialization import pkcs12
from cryptography.x509.oid import NameOID
from cryptography import x509
from datetime import datetime, timedelta
import base64

def generate_pfx_data(pfx_password, common_name, org_name, country_code): # Bỏ pfx_path    # ==========================
    # ✅ Tạo private key RSA 2048
    # ==========================
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )

    # ==========================
    # ✅ Tạo certificate self-signed
    # ==========================
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, country_code),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, org_name),
        x509.NameAttribute(NameOID.COMMON_NAME, common_name),
        # Thêm các trường mặc định khác
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

# ==========================
    # ✅ Đóng gói private_key + cert vào dữ liệu PFX
    # ==========================
    pfx_data = pkcs12.serialize_key_and_certificates(
        name=common_name.encode(),
        key=private_key,
        cert=cert,
        cas=None,
        encryption_algorithm=serialization.BestAvailableEncryption(
            pfx_password.encode()
        ),
    )

    # Trích xuất dữ liệu PEM để hiển thị (Giữ nguyên)
    private_key_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    ).decode('utf-8')

    cert_pem = cert.public_bytes(serialization.Encoding.PEM).decode('utf-8')

    return {
        "pfx_data": base64.b64encode(pfx_data).decode(), # Chuyển byte PFX thành base64 để truyền qua HTTP
        "pfx_password": pfx_password,
        "cn": common_name,
        "org": org_name,
        "private_key_pem": private_key_pem,
        "cert_pem": cert_pem
    }