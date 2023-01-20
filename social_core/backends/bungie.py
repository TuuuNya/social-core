"""
Bungie OAuth2 backend
"""
from urllib.parse import unquote, urlencode
from social_core.backends.oauth import BaseOAuth2


class BungieOAuth2(BaseOAuth2):
    name = "bungie"
    ID_KEY = "membership_id"
    AUTHORIZATION_URL = "https://www.bungie.net/en/oauth/authorize/"
    ACCESS_TOKEN_URL = "https://www.bungie.net/platform/app/oauth/token/"
    REFRESH_TOKEN_URL = "https://www.bungie.net/platform/app/oauth/token/"
    ACCESS_TOKEN_METHOD = "POST"
    REDIRECT_STATE = False
    EXTRA_DATA = [
        ("refresh_token", "refresh_token", True),
        ("access_token", "access_token", True),
        ("expires_in", "expires"),
        ("membership_id", "membership_id"),
        ("refresh_expires_in", "refresh_expires_in"),
    ]

    def auth_url(self):
        """Return redirect url"""
        state = self.get_or_create_state()
        params = self.auth_params(state)
        params.update(self.get_scope_argument())
        params.update(self.auth_extra_arguments())
        params.update({
            'reauth': self.data.get('reauth', 2)
        })
        params = urlencode(params)
        if not self.REDIRECT_STATE:
            # redirect_uri matching is strictly enforced, so match the
            # providers value exactly.
            params = unquote(params)
        return f"{self.authorization_url()}?{params}"

    def auth_html(self):
        """Abstract Method Inclusion"""
        pass

    def auth_headers(self):
        """Adds X-API-KEY and Origin"""
        return {
            "X-API-KEY": self.setting("API_KEY"),
            "Content-Type": "application/x-www-form-urlencoded",
            "Origin": self.setting("ORIGIN"),
            "Accept": "application/json",
        }

    def make_bungie_request(self, url, access_token, kwargs):
        """Helper function to get username data keyed off displayName"""
        headers = self.auth_headers()
        headers["Authorization"] = "Bearer " + access_token
        return self.get_json(url, headers=headers)

    # 这里注释掉redirect_uri的原因是默认获取的redirect_url会和bungie官网设置的不一致，导致请求400
    def auth_complete_params(self, state=None):
        params = {
            'grant_type': 'authorization_code',  # request auth code
            'code': self.data.get('code', ''),  # server response code
            # 'redirect_uri': self.get_redirect_uri(state)
        }
        if not self.use_basic_auth():
            client_id, client_secret = self.get_key_and_secret()
            params.update({
                'client_id': client_id,
                'client_secret': client_secret,
            })
        return params

    def auth_complete(self, *args, **kwargs):
        """Completes login process, must return user instance"""
        self.process_error(self.data)
        state = self.validate_state()
        response = self.request_access_token(
            self.access_token_url(),
            data=self.auth_complete_params(state),
            headers=self.auth_headers(),
            auth=self.auth_complete_credentials(),
            method=self.ACCESS_TOKEN_METHOD,
        )

        self.process_error(response)
        return self.do_auth(
            response["access_token"], response=response, *args, **kwargs
        )

    def do_auth(self, access_token, *args, **kwargs):
        """Finish the auth process once the access_token was retrieved"""
        data = self.user_data(access_token, *args, **kwargs)
        response = kwargs.get("response") or {}
        response.update(data or {})
        if "access_token" not in response:
            response["Response"]["access_token"]["value"] = access_token
        kwargs.update({"response": response, "backend": self})
        return self.strategy.authenticate(*args, **kwargs)

    def user_data(self, access_token, *args, **kwargs):
        """Grab user profile information from Bunige"""
        membership_id = kwargs["response"]["membership_id"]
        url = "https://www.bungie.net/Platform/User/GetBungieNetUser/"
        response = self.make_bungie_request(url, access_token, kwargs)

        dms_url = "https://www.bungie.net/Platform/User/GetMembershipsForCurrentUser/"
        dms_response = self.make_bungie_request(dms_url, access_token, kwargs)
        destinyMemberships = dms_response["Response"]["destinyMemberships"]
        steamMemberships = filter(lambda x: x["membershipType"] == 3, destinyMemberships)
        steamMembership = next(steamMemberships, None)

        if steamMembership:
            primaryMembershipId = steamMembership["membershipId"]

        username = response["Response"]["user"]["displayName"]
        return {"username": username, "uid": membership_id, "last_name": primaryMembershipId}

    def get_user_details(self, response, *args, **kwargs):
        """Return user details from Bungie account"""
        username = response["username"]
        return {
            "first_name": username,
            "username": username,
            "last_name": response["last_name"],
            "uid": response["uid"],
        }
