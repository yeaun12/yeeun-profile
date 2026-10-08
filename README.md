# 예은 소개 페이지 + T08 패스키

T01 고정 커밋 `ca06e1155934ccd193429c0ec11b153ff276bc64`의 공개 소개와 상호작용을 유지하고 새 비공개 영역을 추가했다.

## 실행

Node.js 22에서 `npm ci`, `npm run build`, `npm run dev` 후 http://localhost:3000 을 연다. 로컬에서는 SQLite 파일(local.db)을 사용한다. 패스키는 origin/RP ID에 묶이므로 localhost에서 만든 키를 배포 도메인에서 사용할 수 없다.

## Vercel + Turso 배포

1. 이 브랜치의 코드를 Vercel 프로젝트에 연결한다. Framework Preset은 Other, Build Command는 `npm run build`, Output Directory는 `public`, Node.js는 22.x로 설정한다.
2. Turso의 새 DB를 만들고 서버 환경 변수 `TURSO_DATABASE_URL`, `TURSO_AUTH_TOKEN`을 설정한다. 토큰은 GitHub와 제출 파일에 넣지 않는다. 테이블은 API 최초 호출 시 생성된다.
3. 고정 배포 도메인을 확인하고 `APP_ORIGIN=https://실제도메인`과 `RP_ID=실제도메인`을 설정한다. APP_ORIGIN은 마지막 `/`가 없고 RP_ID는 프로토콜·경로가 없다. 재배포한다. Preview URL은 별도 origin이므로 최종 고정 도메인에서 패스키를 등록한다.
4. 새 시크릿 창에서 공개 페이지·소스 커밋이 로그인 없이 열리는지 확인한다. Vercel 배포 보호가 켜져 있으면 제출용 도메인 접근 설정을 조정한다.

배포 서버는 로컬 파일 DB를 영속 저장소로 사용할 수 없다. Turso 환경 변수가 없으면 배포 완료로 판단하지 않는다.

## 네 흐름의 소스 위치

- 등록: public/private.js → POST /api/register/options → lib/app.mjs challenge() → 기기 WebAuthn → POST /api/register/verify → verifyRegistrationResponse → lib/db.mjs credentials.
- 로그인: POST /api/login/options → challenge() → 기기 서명 → POST /api/login/verify → consume() → verifyAuthenticationResponse → issueSession().
- 로그아웃: POST /api/logout → sessions 해시 삭제 + HttpOnly 쿠키 만료.
- 비공개 조회: GET /api/notes, /api/notes/:id → must() 세션 조회 → SQL WHERE user_id=세션의 user_id. 요청의 userId/owner_id는 권한 결정에 사용하지 않는다.

## 보안과 한계

등록·로그인 질문은 DB에서 120초 동안 저장하고 DELETE RETURNING으로 원자적으로 한 번만 소비한다. 잘못된 서명도 질문을 소비한다. 세션은 HttpOnly/SameSite=Strict(HTTPS에서는 Secure), 1시간 만료이며 DB에는 SHA-256 해시만 보관한다. 공개키·credential ID·카운터·사용자가 선택한 저장소 이름을 보관하고 개인키·비밀번호는 저장하지 않는다. 공개 HTML/JS에 비공개 내용이 없다. 마지막 키 삭제는 409로 막는다. 삭제한 키로 생성된 세션도 폐기한다.

한계: 요청 빈도 제한·IP별 자동 공격 차단은 구현하지 않았다. 계정 생성 남용과 서버/DB 부하 공격은 막지 못한다. 모든 키 저장소를 잃은 경우 별도 신원 확인 복구가 없으며, 마지막 키 삭제 방지만으로 실제 분실을 복구할 수 없다. 패스키 추가·삭제 시 별도 최신 인증 요구는 아직 없다. 공개계정의 존재는 오류 메시지로 추정될 수 있다.

## 증빙과 검사

`npm test`: Chromium 가상 인증기로 실제 WebAuthn 등록 응답과 서명을 만들고 서버 검증을 수행한다. 가상 검사는 실제 기기 등록을 대체하지 않는다. `evidence/automated-requests.json`에 요청·응답과 검사 목록을 기록한다. 가상 인증기의 개인키는 출력하거나 제출하지 않는다.

사이트의 '과제 확인과 기록 내려받기'에서 현재 탭의 요청·응답을 JSON으로 내려받는다. 등록 창의 실제 저장 위치와 UI에서 선택한 저장소가 일치하는지 직접 확인한다. 세션·토큰 값은 내보내지 않는다.

### 실제 기기에서 남길 화면

1. 공개 소개 + 잠긴 비공개 영역(시크릿 창).
2. 등록된 패스키 2개(각 이름·날짜)와 실제 선택한 저장소. 개인 이메일·PIN·비밀값은 가린다.
3. 하나 삭제한 뒤 남은 패스키 로그인 성공. 삭제한 패스키는 실패 또는 선택 불가임을 확인한다.
4. 다른 계정과 상호 자료 조회 거절, 자료 건수 전후 3건. JSON 기록을 함께 내려받는다.
5. 패스키 등록 창 취소 뒤 새 계정/패스키가 저장되지 않았다는 안내.

UI의 로그인 질문 재사용 버튼과 로그아웃 후 직접 요청 검사도 실행한다. 최종 제출은 공개 HTTPS 결과물 URL, 공개 고정 소스 커밋 URL, 설명서와 검사 기록 PDF, 확인 방법 4항목, AI와 내 판단 3항목을 모두 포함한다.
