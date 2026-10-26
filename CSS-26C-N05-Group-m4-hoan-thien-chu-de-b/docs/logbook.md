# Nhật ký điều phối

Một dòng cho một lần bàn giao hoặc một mốc đã qua. Người chấm đọc tệp này khi chấm
tiêu chí kế hoạch và điều phối, nên nó là bằng chứng chứ không phải thủ tục.

| Ngày | Ai | Làm gì | Mốc liên quan |
|---|---|---|---|
| 2026-10-07 | Nguyễn Thị Khánh Linh, có hỗ trợ Copilot | Làm việc trên nhánh riêng; cấu hình thời hạn/phiên token, MFA TOTP cho tài khoản admin demo và biện pháp hạn chế khôi phục mật khẩu; bổ sung test JWT và xuất realm đã lọc credential. Bộ kiểm local hiện có 28 test; health checks và xuất bằng chứng đã qua trên các dịch vụ Compose đang chạy. Chưa xác nhận CI GitHub. | M3 (local; chờ nhóm review và CI) |
| 2026-10-08 | Nguyễn Thị Khánh Linh, có hỗ trợ Copilot | Bổ sung ba demo app OIDC Authorization Code + PKCE và 4 test tự động; `make test` (32 test) và `make verify` đều qua. Người thực hiện xác nhận đã kiểm thử tương tác các ca admin đăng nhập TOTP và gọi API admin trên ba ứng dụng, OTP sai/bỏ trống, user thường gọi API user nhưng bị từ chối ở API admin, và workflow CI GitHub chạy thành công. Application 1 được quan sát trả HTTP 200 cho API admin. | M3 (local; chờ nhóm review) |
| 2026-10-19 | Đỗ Trung Kiên, có hỗ trợ Claude | Chuyển kho sang cấu trúc đặc tả (`compose/`, `config/`, `evidence/`, `docs/`); thêm target `preflight/attack/defend/export-evidence`, `MANIFEST.txt`, `threat-model.json`, báo cáo và slides. Chưa chạy Docker; chưa chạy `make attack`; chưa có SBOM/cosign. | M4 (chuẩn bị; chờ nhóm review và CI) |
| 2026-10-23 | Đỗ Trung Kiên, có hỗ trợ OpenAI Codex | Sửa Makefile để test và verify dùng đường dẫn repo ổn định; tách test cấu hình realm khỏi image Resource Server; ghim digest base image Python; cập nhật báo cáo từ kết quả 18 ca tấn công sống và 41 test pytest + 3 subtest. Thành viên xác nhận `make verify` đạt; log `make test` gần nhất cho thấy hai image build thành công, 22 test Resource Server và 4 test demo đều đạt. Pytest chạy trên máy phát triển. | M4 (hoàn thiện bằng chứng; còn chờ các mục cần xác nhận nhóm và CI cuối) |
