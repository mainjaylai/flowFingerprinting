import requests

def search_threads(page):
    url = 'https://liuyan.people.com.cn/v2/threads/search?sortType=0'
    
    headers = {
        'Content-Type': 'application/json',
        'Cookie': '__jsluid_s=98513ae31c6de48d356e885f402f7bf7',
    }

    data = {
        "appCode": "PC42ce3bfa4980a9",
        "signature": "bec2facf4f2a6ea58ced5215c60e6c1c",
        "param": {
            "position": 0,
            "keywords": "天然气",
            "fid": None,
            "domainId": None,
            "typeId": None,
            "timeRange": None,
            "ansChecked": False,
            "stTime": None,
            "sortType": "0",
            "page": page,  # page is variable here
            "rows": 10
        }
    }

    response = requests.post(url, json=data, headers=headers)
    
    # Check if request was successful
    if response.status_code == 200:
        return response.json()
    else:
        return {"error": response.status_code, "message": response.text}

# Example usage:
result = search_threads(page=1)
print(result)
