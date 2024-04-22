
import base64
import json
import hashlib
import bcrypt
from argon2 import PasswordHasher


def encode(passwd): 
	encoded = base64.b64encode(passwd.encode("utf-8"))
	return encoded.decode("utf-8") 

def hash(passwd): 
	hash_object = hashlib.sha256()
	hash_object.update(passwd.encode("utf-8"))
	hash_password = hash_object.hexdigest()
	return hash_password

def hash_salt(passwd,salt): 
	hash_object = hashlib.sha256()
	hash_object.update(passwd.encode("utf-8")+salt.encode("utf-8"))
	hashed_password = hash_object.hexdigest()
	return hashed_password

def work_factors(passwd,hashed): 
	# salt = bcrypt.gensalt()
	# hashed_password = bcrypt.hashpw(passwd.encode("utf-8"), salt.encode("utf-8"))
	result = bcrypt.checkpw(passwd.encode("utf-8"), hashed.encode("utf-8")) 
	return result
def upgrade_work_factors(passwd,hashed): 

	ph = PasswordHasher(
	    memory_cost=2**16,
	    time_cost=2,
	    parallelism=1,
	    hash_len=32,
	    salt_len=16
	)
	# hashed = ph.hash(i)
	result = ph.verify(hashed, passwd)
	return result

if __name__ == "__main__":

	inputpassword = "BizhOKiP"

	f = open('members.json')
	data = json.load(f)
	#--------------- PLAINTEXT -----------------------
	for i in data['plaintext']:
		if inputpassword == i["password"]:
			print(i)

	#---------------  ENCODE  ------------------------
	# for i in data['encode']:
	# 	if  encode(inputpassword) == i["password"]:
	# 		print(i)
	#-----------------  HASH  ------------------------
	# for i in data['hash']:
	# 	if  hash(inputpassword) == i["password"]:
	# 		print(i)
	#---------------  HASH + SALT  -------------------
	# for i in data['hash_salt']:
	# 	if  hash_salt(inputpassword,i["salt"]) == i["password"]:
	# 		print(i)
	#---------------  WORK FACTORS  ------------------
	# for i in data['bcrypt']:
	# 	if  work_factors(inputpassword,i["password"]):
	# 		print(i)
	#------------  Upgrade WORK FACTORS  --------------
	# for i in data['argon2']:
	# 	try:
	# 		if  upgrade_work_factors(inputpassword, i["password"]):
	# 			print(i)
	# 	except:
	# 		print("")
 

	






