# NetApp AutoSupport Analyzer

ONTAP AutoSupport 압축 파일이나 압축 해제 폴더를 업로드하면 필요한 구성 정보를 추출하고, 결과를 작은 JSON 리포트로 저장하는 로컬 웹 도구입니다.

## 실행

```powershell
python server.py
```

브라우저에서 아래 주소를 엽니다.

```text
http://127.0.0.1:8765
```

## 사용 흐름

1. `.7z` 또는 `.zip` AutoSupport 파일을 여러 개 선택합니다.
2. 또는 이미 압축 해제된 AutoSupport 폴더를 선택합니다.
3. `분석하고 JSON 저장`을 누릅니다.
4. 분석이 끝나면 `reports/` 아래에 JSON 리포트만 저장됩니다.
5. 원본 업로드 파일과 임시 추출 파일은 자동 삭제됩니다.

## 저장 구조

- `reports/*.json`: 저장된 분석 결과
- `uploads/`: 업로드 임시 폴더, 분석 후 삭제
- `work/extracted/`: 압축 해제 임시 폴더, 분석 후 삭제

화면은 저장된 JSON을 다시 읽어서 보여주므로, 여러 클러스터를 저장해도 원본 AutoSupport 파일을 계속 들고 있는 방식보다 가볍게 동작합니다.
