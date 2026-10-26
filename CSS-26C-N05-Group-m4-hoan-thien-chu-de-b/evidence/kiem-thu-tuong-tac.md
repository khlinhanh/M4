# Ghi nhận kiểm thử tương tác OIDC/TOTP

- **Người thực hiện:** Nguyễn Thị Khánh Linh (theo `docs/logbook.md`).
- **Ngày thực hiện:** 2026-10-08.
- **Nguồn ghi nhận:** nội dung xác nhận trong `docs/logbook.md`; đây là biên bản tường thuật, không phải log máy tự sinh.
- **Phạm vi:** ba ứng dụng demo OIDC và ba resource server local.

| Ca kiểm | Kết quả được ghi nhận | Mức bằng chứng |
|---|---|---|
| Admin nhập TOTP đúng | Đăng nhập hoàn tất sau TOTP; gọi API admin thành công trên cả ba ứng dụng. | Người thực hiện xác nhận; phản hồi HTTP 200 `Admin API access granted` được quan sát ở Application 1. Không có phản hồi HTTP lưu cho Application 2 và 3. |
| Admin nhập OTP sai | Không hoàn tất đăng nhập về ứng dụng. | Người thực hiện xác nhận trong logbook; không có log trình duyệt hoặc HTTP lưu. |
| Admin bỏ trống OTP | Không hoàn tất đăng nhập về ứng dụng. | Người thực hiện xác nhận trong logbook; không có log trình duyệt hoặc HTTP lưu. |
| User thường | Gọi API user thành công; API admin từ chối. | Người thực hiện xác nhận trong logbook; không có phản hồi HTTP lưu. |

Không ghi TOTP seed, mã dự phòng, mật khẩu, cookie hay access token vào tệp này.
