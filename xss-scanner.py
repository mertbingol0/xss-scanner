from bs4 import BeautifulSoup as bs 
from urllib.parse import urljoin
import requests 


def get_all_forms(url):
    soup = bs(requests.get(url).content,"html.parser") #Burada tum htmli urlden istiyoruz.
    return soup.find_all("form") #Bu kisimda da sadece "form" icerigini dondurmesini soyluyoruz.
    
#Bu fonksyonda ise form icersinde ki inputlardan tum degerleri alip detailsin icersine return ediyoruz.
def get_forms_details(form):
    details = {}

    action = form.attrs.get("action").lower() #Bu satirda form kisminda bir search islemi yapildiginda urldeki action degerini aliyoruz.
    method = form.attrs.get("method","get").lower() #lower() fonksyonu stringleri kucultmeye yarar. Ornek: mErt = mert

    inputs = [] 
    for input_tag in form.find_all("input"): # Burada form icersinde ki input degerlerini aliyoruz.
        input_type = input_tag.attrs.get("type","text") #Burada yukaridaki satirda yaptigimiz input alma isleminin icerisindeki type degerini aliyoruz. Fakat burada aldigimiz type degerinin "text" olacagini da soyluyoruz.
        input_name = input_tag.attrs.get("name") #Burada da yine yukaridaki gibi input icerisinde ki name parametresinin degerini aliyoruz.
        inputs.append({"type": input_type, "name":input_name}) #Burada for icinde aldigimiz tum degerleri, inputs dizisine veriyoruz.

    details["action"] = action 
    details["method"] = method
    details["inputs"] = inputs 

    return details 
#Bu fonksiyonda ise details fonksyonundaki inputlara payload islemi yapcagiz. Yani inputlara xss testimizi gerceklestirecegiz.
def submit_forms(form_details,url,value):

    target_url = urljoin(url,form_details["action"]) #Burada url'i ve action kismini verip target_url adi altinda bunlari toparlayacak.

    inputs = form_details["inputs"] #form detailden vermis oldugumuz inputu inputs degiskenine atiyoruz.
    data  = {}

#inputlar
    for input in inputs:
        if input["type"] == "text" or input["type"] == "search": #eger aldimiz input degerinin type'i text ise yada search ise bu kosula gir ve value ile xss payloadimizi input'a ver.
            input["value"] = value 
            input_name = input.get("name")
            input_value = input.get("value")
            if input_name and input_value : # yukarida ki iki degerde olusturulduysa bu kosulu calistir.
                data[input_name] = input_value 
            if form_details["method"] == "post": # eger method degeri post ise, post metodu requesti at.
                return requests.post(target_url,data=data)
            else: # eger method degeri post degilse, get metodu ile request at.
                return requests.get(target_url,params=data)

#Burada da alinan url uzerinde xss zafiyeti icin bir payload islemi yapiliyor.
def xss_scanner (url):
    forms = get_all_forms(url)
    print("Searching for XSS vulnerability...")
    xss_payload = "<script>alert('xss-test')</script>"
    is_vuln = False 
    for form in forms: #bazi sitelerde birden fazla form bolumu olabiliyor. Bu nedenle tum formlari inceleyecek bir dongu yazdik.
        form_details = get_forms_details(form)
        content = submit_forms(form_details,url,xss_payload).content.decode()
        if  xss_payload in content: #Eger xss_payload degerimiz bize donen response icerisinde varsa zafiyet vardir.
            print("XSS vulnerability detected!")
            is_vuln = True
    return is_vuln 

if __name__ == "__main__":
    url = input("Enter site address for XSS search: ")
    is_vulne = xss_scanner(url)
