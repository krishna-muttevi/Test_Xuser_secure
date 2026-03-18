default creds:

admin->  admin:rangerR0cks!  1 , validuser1244:rangerR0cks! 62
keyadmin->  keyadmin:rangerR0cks! 3 , mkrishna:rangerR0cks!  37
auditor->   pytest_user_wepdf:Test@123  44 , pytest_user_qugmh:Test@123 48
user->  pytest_user_opugl:Test@123 53 , pytest_user_ylwze:Test@123 55


"user": "ROLE_USER",
"admin": "ROLE_SYS_ADMIN",
"auditor": "ROLE_ADMIN_AUDITOR"
""keyadmin": "ROLE_KEY_ADMIN"


auditors : id (44, 48)
key admins : id (3, 37)


curl -v -X PUT 'http://localhost:6080/service/xusers/secure/users/roles/44' \
  -u 'keyadmin:rangerR0cks!' \
  -H 'Accept: application/json' \
  -H 'Content-Type: application/json' \
  -H 'X-Requested-By: ranger' \
  -d '{
    "vXStrings": [
      {"value": "ROLE_ADMIN_AUDITOR"}
    ]
  }'




key admin in beaver:
SELECT id, user_name FROM x_user WHERE user_name = 'mkrishna'; % id is 37, password: Vpbms@940


UPDATE x_portal_user_role 
SET user_role = 'ROLE_KEY_ADMIN', update_time = current_timestamp 
WHERE user_id = getXportalUIdByLoginId('mkrishna');

http://localhost:6080/service/

for active status update, use the following command:
curl -X PUT -u admin:rangerR0cks! -H "Accept: application/json" -H "Content-Type: application/json" -d '{"113": 0}' "http://localhost:6080/service/xusers/secure/users/activestatus"
"
for bulk delete
curl -X DELETE "http://localhost:6080/service/xusers/secure/users/delete?forceDelete=true" \
-u admin:rangerR0cks! \
-H "Content-Type: application/json" \
-H "X-Requested-By: ranger" \
-d '{
  "listSize": 2,
  "list": [
    { "value": "user1" },
    { "value": "user2" }
  ]
}'


for secure/role:
curl -v -X PUT 'http://localhost:6080/service/xusers/secure/users/roles/49' \
  -u 'admin:rangerR0cks!' \
  -H 'Accept: application/json' \
  -H 'Content-Type: application/json' \
  -H 'X-Requested-By: ranger' \
  -d '{
    "vXStrings": [
      {"value": "ROLE_SYS_ADMIN"}
    ]
  }'

  but also giving ok for

error :
mkrishna@M02Y5Q9N02 ~ % curl -v -X PUT 'http://localhost:6080/service/xusers/secure/users/roles/49' \
  -u 'admin:rangerR0cks!' \
  -H 'Accept: application/json' \
  -H 'Content-Type: application/json' \
  -H 'X-Requested-By: ranger' \
  -d '{
    "vXStrings": [
      {"eeiu": "ROLE_USER"}     
    ]
  }'
* Host localhost:6080 was resolved.
* IPv6: ::1
* IPv4: 127.0.0.1
*   Trying [::1]:6080...
* Connected to localhost (::1) port 6080
* Server auth using Basic with user 'admin'
> PUT /service/xusers/secure/users/roles/49 HTTP/1.1
> Host: localhost:6080
> Authorization: Basic YWRtaW46cmFuZ2VyUjBja3Mh
> User-Agent: curl/8.7.1
> Accept: application/json
> Content-Type: application/json
> X-Requested-By: ranger
> Content-Length: 58
> 
* upload completely sent off: 58 bytes
< HTTP/1.1 200 
< Set-Cookie: RANGERADMINSESSIONID=CAA71D8A6C36E492DF9506D4DF93A8D1; Path=/; HttpOnly
< Cache-Control: no-cache, no-store, max-age=0, must-revalidate
< X-Frame-Options: DENY
< X-XSS-Protection: 1; mode=block
< Strict-Transport-Security: max-age=31536000; includeSubDomains; preload
< Content-Security-Policy: default-src 'none'; script-src 'self' 'unsafe-inline' 'unsafe-eval'; connect-src 'self'; img-src 'self' data:; style-src 'self' 'unsafe-inline';font-src 'self'
< X-Permitted-Cross-Domain-Policies: none
< X-Content-Type-Options: nosniff
< Content-Type: application/json
< Transfer-Encoding: chunked
< Date: Wed, 04 Mar 2026 11:37:26 GMT
< Server: Apache Ranger
< 
* Connection #0 to host localhost left intact
{"startIndex":0,"pageSize":1,"totalCount":1,"resultSize":1,"queryTimeMS":1772624246632,"vXStrings":[{"value":"ROLE_SYS_ADMIN"}]}%                                                                                                               mkrishna@M02Y5Q9N02 ~ % 


mkrishna@M02Y5Q9N02 ~ % curl -u admin:rangerR0cks! \
  -H "Content-Type: application/json" \
  -H "X-Requested-By: ranger" \
  -X POST \
  http://localhost:6080/service/xusers/users \
  -d '{
    "name": "my_user",
    "password": "Test@123",
    "isVisible": 1
  }'
"
{"id":6957,"createDate":"2026-03-10T10:58:49Z","updateDate":"2026-03-10T10:58:49Z","owner":"Admin","updatedBy":"Admin","name":"my_user","groupIdList":[],"groupNameList":[],"status":0,"isVisible":1,"userSource":0,"userRoleList":["ROLE_USER"]}% mkrishna@M02Y5Q9N02 ~ % curl -u admin:rangerR0cks! \
-H "Content-Type: application/json" \  
-H "X-Requested-By: ranger" \  
-X POST \  
http://localhost:6080/service/xusers/users \       
-d '{  
  "name": "curyeghbxbl_user_test",   
  "firstName": "Curl",     
  "lastName": "Test",
  "emailAddress": "curl_user_test@test.com",
  "password": "Test@123",
  "status": 1,
  "isVisible": 1,
  "userRoleList": ["ROLE_SYS_ADDMIN"],
  "groupIdList": [],
  "groupNameList": []
}' 
{"id":6956,"createDate":"2026-03-10T10:23:36Z","updateDate":"2026-03-10T10:23:36Z","owner":"Admin","updatedBy":"Admin","name":"curyeghbxbl_user_test","groupIdList":[],"groupNameList":[],"status":0,"isVisible":1,"userSource":0,"userRoleList":["ROLE_USER"]}%      


@ put /users:

curl -i -u admin:rangerR0cks! \
  -H "Content-Type: application/json" \
  -H "X-Requested-By: ranger" \
  -X PUT \
  http://localhost:6080/service/xusers/users \
  -d '{
    "id": 55,
    "name": "pytest_user_ylwze",
    "firstName": "Myfirsts",
    "userRoleList": ["ROLE_SYS_ADMIN"], "lastName": "lasty"            
  }'

curl -i -u pytest_user_opugl:Test@123 \
  -H "Content-Type: application/json" \
  -H "X-Requested-By: ranger" \
  -X PUT \
  http://localhost:6080/service/xusers/users \
  -d '{
    "id": 53,
    "name": "pytest_user_opugl",
    "firstName": "Myfirsts",
    "userRoleList": ["ROLE_ADMIN_AUDITOR"], "lastName": "lasty"            
  }'