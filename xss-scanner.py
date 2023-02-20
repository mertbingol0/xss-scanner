"""
xss-scanner
Author: mertbingol0
Date: 11/13/2022
"""

# Define a function to retrieve all the forms present on the webpage
def get_all_forms(url):
    soup = bs(requests.get(url).content, "html.parser")
    return soup.find_all("form")

# Define a function to retrieve all the details of a given form
def get_forms_details(form):
    details = {}
    
    # Extract the 'action' attribute of the form
    action = form.attrs.get("action").lower()
    
    # Extract the 'method' attribute of the form
    method = form.attrs.get("method", "get").lower()
    
    # Extract the 'name' and 'type' attributes of all input fields of the form
    inputs = []
    for input_tag in form.find_all("input"):
        input_type = input_tag.attrs.get("type", "text")
        input_name = input_tag.attrs.get("name")
        inputs.append({"type": input_type, "name": input_name})
    
    # Store the form details in a dictionary
    details["action"] = action
    details["method"] = method
    details["inputs"] = inputs
    
    return details

# Define a function to submit a form with an XSS payload
def submit_forms(form_details, url, value):
    target_url = urljoin(url, form_details["action"])
    inputs = form_details["inputs"]
    data = {}
    
    # For each input field, set its value to the XSS payload if it is of type 'text' or 'search'
    for input in inputs:
        if input["type"] == "text" or input["type"] == "search":
            input["value"] = value
            input_name = input.get("name")
            input_value = input.get("value")
            if input_name and input_value:
                data[input_name] = input_value
        
        # If the form method is 'POST', make a POST request with the form data
        if form_details["method"] == "post":
            return requests.post(target_url, data=data)
        # If the form method is not 'POST', make a GET request with the form data
        else:
            return requests.get(target_url, params=data)

# Define a function to scan a webpage for XSS vulnerabilities
def xss_scanner(url):
    forms = get_all_forms(url)
    print("Searching for XSS vulnerability...")
    xss_payload = "<script>alert('xss-test')</script>"
    is_vuln = False
    
    # For each form on the webpage, submit it with an XSS payload and check if the payload is present in the response
    for form in forms:
        form_details = get_forms_details(form)
        content = submit_forms(form_details, url, xss_payload).content.decode()
        if xss_payload in content:
            print("XSS vulnerability detected!")
            is_vuln = True
    
    return is_vuln

# If the script is run from the command line, prompt the user for a URL to scan and call the 'xss_scanner' function
if __name__ == "__main__":
    url = input("Enter site address for XSS search: ")
    is_vulne = xss_scanner(url)
