import os, time
import requests, json, byu_jwt


class JWT_Test:
    def __init__(self):
        self.raw_jwt = self._retrieve_jwt()
        self.jwt_handler = byu_jwt.JWT_Handler()

    def _retrieve_jwt(self):
        client_id = os.environ.get('WSO2_CLIENT_ID')
        client_secret = os.environ.get('WSO2_CLIENT_SECRET')

        token_url = "https://api.byu.edu/token"
        data = {'grant_type': 'client_credentials'}
        token_response = requests.post(token_url,
                                        data=data,
                                        allow_redirects=False,
                                        auth=(client_id, client_secret))

        tokens = json.loads(token_response.text)

        echo_url = "https://api.byu.edu/echo/v1/echo/hello_world"
        echo_headers = {'Authorization': 'Bearer ' + tokens['access_token']}
        echo_response = requests.get(echo_url, headers=echo_headers)

        echo_response = json.loads(echo_response.text)
        return echo_response['Headers']['X-Jwt-Assertion'][0]

    def test_valid_jwt(self):
        assert self.jwt_handler.is_valid(self.raw_jwt)

    def test_jwt_payload(self):
        jwt = self.jwt_handler.decode(self.raw_jwt)
        assert jwt['iss'] == 'https://api.byu.edu'
        assert jwt['exp'] > time.time()
        assert 'byu'                    in jwt
        assert 'client'                 in jwt['byu']
        assert 'byuId'                  in jwt['byu']['client']
        assert 'claimSource'            in jwt['byu']['client']
        assert 'netId'                  in jwt['byu']['client']
        assert 'personId'               in jwt['byu']['client']
        assert 'preferredFirstName'     in jwt['byu']['client']
        assert 'prefix'                 in jwt['byu']['client']
        assert 'restOfName'             in jwt['byu']['client']
        assert 'sortName'               in jwt['byu']['client']
        assert 'subscriberNetId'        in jwt['byu']['client']
        assert 'suffix'                 in jwt['byu']['client']
        assert 'surname'                in jwt['byu']['client']
        assert 'surnamePosition'        in jwt['byu']['client']
        assert 'wso2'                   in jwt
        assert 'application'            in jwt['wso2']


def test_run():
    test_runner = JWT_Test()
    test_runner.test_valid_jwt()
    test_runner.test_jwt_payload()
