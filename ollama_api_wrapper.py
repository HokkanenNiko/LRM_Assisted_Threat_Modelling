import requests

class OllamaAPIWrapper:
    def __init__(self, base_url, api_key = ''):
        self.base_url = base_url
        self.api_key = api_key
        self.headers = {'Content-Type': 'application/json'}
        if self.api_key != '':
            self.headers['Authorization'] = f'Bearer {self.api_key}'

    def get(self, endpoint, params=None):
        url = f'{self.base_url}/{endpoint}'
        response = requests.get(url, headers=self.headers, params=params)
        return self._handle_response(response)

    def post(self, endpoint, data=None):
        url = f'{self.base_url}/{endpoint}'
        response = requests.post(url, headers=self.headers, json=data)
        return self._handle_response(response)

    def put(self, endpoint, data=None):
        url = f'{self.base_url}/{endpoint}'
        response = requests.put(url, headers=self.headers, json=data)
        return self._handle_response(response)

    def delete(self, endpoint):
        url = f'{self.base_url}/{endpoint}'
        response = requests.delete(url, headers=self.headers)
        return self._handle_response(response)

    def _handle_response(self, response):
        if response.status_code == 200:
            return response.json()
        else:
            response.raise_for_status()
