# send-booking-email (Supabase Edge Function)

ダッシュボードの Edge Functions エディタから作成・デプロイ済み。
- 入力: `{ type: "new_request" | "approved" | "rejected", bookingId }`
- bookings テーブルから該当予約を読み、Resend API でメール送信
- 必要な Secrets: `RESEND_API_KEY`, `OWNER_EMAIL`（SUPABASE_URL / SERVICE_ROLE_KEY は自動付与）
- 送信元は独自ドメイン認証までは `onboarding@resend.dev`（宛先はResendアカウント所有者のみ）
- 独自ドメイン認証後は `FROM_ADDRESS` を変更して再デプロイする
