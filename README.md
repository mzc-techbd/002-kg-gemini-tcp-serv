# TCP 서버 (Gemini API 연동)

간단한 C++ TCP 서버 애플리케이션입니다.  
클라이언트로부터 메시지를 받아 Google Gemini API를 호출하고, 그 결과를 클라이언트에게 다시 전송합니다.


## 준비 과정

### 필수 요구사항

*   **C++ 컴파일러:** C++17 이상을 지원하는 컴파일러 (예: GCC, Clang)
*   **CMake:** 빌드 시스템 (버전 3.11 이상)
*   **libcurl:** HTTP 요청을 위한 라이브러리
*   **OpenSSL:** HTTPS 통신 및 암호화 라이브러리
*   **nlohmann/json:** json 라이브러리

**macOS (Homebrew 사용 시):**

```bash
brew install cmake curl openssl
```

**Ubuntu/Debian (apt 사용 시):**

```bash
sudo apt update
sudo apt install build-essential cmake libcurl4-openssl-dev libssl-dev
```

### Google Cloud 설정

1.  **Google Cloud 프로젝트 생성 및 API 활성화:**
    *   Google Cloud Console ([https://console.cloud.google.com/](https://console.cloud.google.com/))에서 새 프로젝트를 생성하거나 기존 프로젝트를 선택합니다.
    *   "API 및 서비스" > "라이브러리"에서 "Vertex AI API" (또는 사용하려는 특정 Gemini API)를 검색하고 활성화합니다.
2.  **서비스 계정 키 생성:**
    *   "API 및 서비스" > "사용자 인증 정보"로 이동합니다.
    *   "사용자 인증 정보 만들기" > "서비스 계정"을 선택합니다.
    *   필요한 정보를 입력하고 서비스 계정을 생성합니다. 역할은 최소한 "Vertex AI 사용자" 또는 API 호출에 필요한 권한을 포함해야 합니다.
    *   생성된 서비스 계정 이메일을 클릭하고 "키" 탭으로 이동합니다.
    *   "키 추가" > "새 키 만들기"를 선택하고 "JSON" 형식을 선택한 후 키 파일을 다운로드합니다.
    *   다운로드한 JSON 키 파일의 이름을 `service-account-key.json`으로 변경하고, 이 프로젝트의 루트 디렉토리에 위치시킵니다.  
    > **주의: 이 파일은 민감한 정보를 담고 있으므로 Git 저장소 등에 커밋하지 않도록 `.gitignore`에 추가하는 것이 좋습니다.** (이미 `.gitignore`에 포함되어 있을 수 있습니다.)

### 의존성 라이브러리 (자동 설치)

*   **nlohmann/json:** JSON 파싱 라이브러리
*   **spdlog:** 로깅 라이브러리

이 라이브러리들은 CMake의 `FetchContent` 기능을 통해 빌드 시 자동으로 다운로드 및 설정됩니다.

## 빌드 방법

1.  **빌드 디렉토리 생성 및 이동:**

    ```bash
    mkdir build
    cd build
    ```

2.  **CMake 실행:**

    *   **기본 빌드:**

        ```bash
        cmake ..
        ```

    *   **옵션과 함께 빌드:**
        *   `VERBOSE_LOG`: 상세 로깅 활성화 (`ON`/`OFF`, 기본값 `OFF`)
        *   `USE_STREAMING_API`: Gemini API 호출 시 스트리밍 방식 사용 여부 (`ON`/`OFF`, 기본값 `OFF`)

        예시 (상세 로깅 활성화):

        ```bash
        cmake .. -DVERBOSE_LOG=ON
        ```

        예시 (스트리밍 API 사용):

        ```bash
        cmake .. -DUSE_STREAMING_API=ON
        ```

3.  **컴파일:**

    ```bash
    make
    ```

    또는 병렬 빌드를 위해:

    ```bash
    make -j$(nproc) # Linux
    make -j$(sysctl -n hw.ncpu) # macOS
    ```

## 실행 방법

빌드가 성공적으로 완료되면 `build` 디렉토리 안에 `tcp-server` 실행 파일이 생성됩니다.

```bash
./build/tcp-server
```

서버가 시작되고 기본 포트(예: 8080)에서 클라이언트 연결을 기다립니다. 다른 터미널에서 `telnet`이나 `nc` 같은 도구를 사용하여 서버에 접속하고 메시지를 보낼 수 있습니다.

**예시 (telnet 사용):**

```bash
telnet localhost 8080
```

연결 후 메시지를 입력하면 서버는 해당 메시지를 Gemini API로 보내고 응답을 받아 다시 클라이언트에게 전송합니다.