# 중고거래 웹 플랫폼

Flask 기반의 소형 중고거래 플랫폼입니다.  
---

## 주요 기능

- 회원가입 / 로그인 / 로그아웃
- 사용자 프로필 관리 (소개글, 비밀번호 변경)
- 상품 등록 / 조회 / 상세 페이지 / 내 상품 관리
- 상품별 1:1 실시간 채팅 기능 (Socket.IO 기반)
- 사용자 간 송금 기능
- 신고 기능 (상품/유저)
- 관리자 페이지 (전체 사용자, 상품, 신고 내역 관리)
- 신고 누적 시 자동 비활성화 / 휴면계정 전환
---
## 실행 환경

- Python 3.9+
- Flask
- SQLite

## 설치 방법

### 1. 가상 환경 설치 (Anaconda or Miniconda 필요)

```bash
git clone https://github.com/ugonfor/secure-coding.git
cd secure-coding
conda env create -f environment.yaml
conda activate secure-coding

# 패키지 설치
pip install -r requirements.txt

# 서버 실행
python app.py
