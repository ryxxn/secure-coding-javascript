# secure-coding-javascript

## Contents

1. 입력 데이터 검증 및 표현
   (1) [SQL 삽입](#1-1)
   (2) [코드 삽입](#1-2)
   (3) [경로 조작 및 자원 삽입](#1-3)
   (4) [XSS](#1-4)
   (5) [운영체제 명령어 삽입](#1-5)
   (6) [위험한 형식 파일 업로드](#1-6)
   (7) [신뢰되지 않은 URL주소로 자동접속 연결](#1-7)
   (8) [부적절한 XML 외부 개체 참조]($1-8)
   (9) [XML 삽입](#1-9)
   (10) [LDAP 삽입](#1-10)
   (11) [크로스사이트 요청 위조(CSRF)](#1-11)
   (12) [서버사이드 요청 위조](#1-12)
   (13) [보안기능 결정에 사용되는 부적절한 입력값](#1-13)

- 2. 보안 기능

- 3. 시간 및 상태

- 4. 에러처리

- 5. 코드 오류

- 6. 캡슐화

- 7. API 오용

---

### 1-1 SQL 삽입 {#1-1}

쿼리 검증을 하지 않으면 외부 입력값으로 인한 SQL 삽입 공격이 발생할 수 있다.

**Bad:**

```javascript
router.get('/vuln/email', (req, res) => {
  const con = connection;
  const userInput = req.query.id;
  // 사용자로부터 입력받은 값을 검증 없이 그대로 쿼리에 사용
  const query = `SELECT email FROM user WHERE user_id = ${userInput}`;
  con.query(query, (err, result) => {
    if (err) console.log(err);
    return res.send(result);
  });
});
```

**Good:**

```javascript
router.get("/patched/email", (req, res) => {
  const con = connection;
  const userInput = req.query.id;
  const query = ‘SELECT email FROM user WHERE user_id = ?‘;
  // 쿼리 함수에 사용자 입력값을 매개변수 형태로 전달, 이렇게 작성하면 사용자 입력값에
  // escape 처리를 한 것과 동일한 결과가 실행
  con.query(query, userInput,
    (err, result) => {
      if (err) console.log(err);
      return res.send(result);
    }
  );
});
```

---

### 1-2 코드 삽입 {#1-2}

**Bad:**

```javascript
router.post('/vuln/server', (req, res) => {
  // 사용자로부터 전달 받은 값을 그대로 eval 함수의 인자로 전달
  const data = eval(req.body.data);
  return res.send({ data });
});
```

**Good:**

```javascript
function alphanumeric(input_text) {
  // 정규표현식 기반 문자열 검사
  const letterNumber = /^[0-9a-zA-Z]+$/;
  if (input_text.match(letterNumber)) {
    return true;
  } else {
    return false;
  }
}
router.post("/patched/server", (req, res) => {
  let ret = null;
  const { data } = req.body;
  // 사용자 입력을 영문, 숫자로 제한하며, 만약 입력값 내에 특수문자가 포함되어
  // 있을 경우 에러 메시지를 반환
  if (alphanumeric(data)) {
    ret = eval(data);
  } else {
    ret = ‘error’;
  }
  return res.send({ ret });
});
```

---

### 1-3 경로 조작 및 자원 삽입{#1-3}

**Bad:**

```javascript
const express = require('express');
const path = require('path');

router.get('/vuln/file', (req, res) => {
  // 외부 입력값으로부터 파일명을 입력 받음
  const requestFile = req.query.file;
  // 입력값을 검증 없이 파일 처리에 사용
  fs.readFile(
    path.resolve(__dirname, requestFile),
    'utf8',
    function (err, data) {
      if (err) {
        return res.send('error');
      }
      return res.send(data);
    }
  );
});
```

**Good:**

```javascript
const express = require('express');
const path = require('path');

router.get('/patched/file', (req, res) => {
  const requestFile = req.query.file;
  // 정규표현식을 사용해 사용자 입력값을 필터링
  const filtered = requestFile.replace(/[.\\\/]/gi, '');
  fs.readFile(filtered, 'utf8', function (err, data) {
    if (err) {
      return res.send('error');
    }
    return res.send(data);
  });
});
```
