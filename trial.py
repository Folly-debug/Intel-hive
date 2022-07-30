from bs4 import BeautifulSoup
from fake_useragent import UserAgent
from colorama import Fore, Back, Style
import requests, string, re

def hackernews():
    ua = UserAgent()
    header = {'User-Agent': str(ua.chrome)}
    link = "https://thehackernews.com/"
    response = requests.get(link, timeout=5, headers=header)
    if response.status_code == 200:
        print("-" * 70)
        print("Webite: " + Fore.GREEN + link)
        print(Fore.WHITE + "Status: " + Fore.GREEN + "UP")
    else:
        exit()
    soup = BeautifulSoup(response.content, "html.parser")
    menu = soup.find_all('li', attrs={"class": "show-menu"})
    title = soup.title
    for links in soup.find_all('a', attrs={"class": "story-link"}):
        news_url=links.get('href')
        
        title = f"{''.join(x for x in links.text if x in string.printable).strip()[:80]}...."
        content = ''.join(x for x in links.text if x in string.printable).strip()
        print(f'URL: {news_url}, \n TITLE : {title}, CONTENT : {content}')

hackernews()