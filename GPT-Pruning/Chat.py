import requests

class Chat:
    def __init__(self, api_key: str) -> None:
        self.api_key = api_key

    def analyze_issue_with_gpt4(self, system_prompt: str, user_prompt: str):
        headers = {
            "Authorization": f"Bearer {self.api_key}"
        }

        if system_prompt == "":
            messages = [
                {"role": "user", "content": user_prompt}
            ]
        else:
            messages = [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt}
            ]

        data = {
            "model": "gpt-4o",
            "messages": messages
        }

        try:
            response = requests.post("gpt_api_requrest_url", json=data, headers=headers)
            if response.status_code == 200:
                response_json = response.json()
                if response_json['choices']:
                    return response_json['choices'][0]['message']['content']
                else:
                    print("无法获取分析结果")
                    return "error"
            else:
                print(response.status_code, response.text)
                return "error"
        except Exception as e:
            print(f"OpenAI API 请求出错: {e}")
            return "error"
