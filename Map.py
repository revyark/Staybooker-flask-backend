import os
import requests
from dotenv import load_dotenv

load_dotenv()
key = os.getenv("OPENCAGE_API_KEY")
address = "1600 Amphitheatre Pkwy, Mountain View, CA"
url = f"https://api.opencagedata.com/geocode/v1/json?q={address}&key={key}"

res = requests.get(url)
data = res.json()

if data['results']:
    latlng = data['results'][0]['geometry']
    print("Lat:", latlng['lat'], "Lng:", latlng['lng'])
else:
    print("No results found.")
