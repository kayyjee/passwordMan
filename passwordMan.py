#!/usr/bin/env python
from pymongo import MongoClient
from Crypto.Cipher import AES
client = MongoClient()
db = client.passwordMan
import re
import bcrypt
import getpass
import time
import sys
import hashlib
import bson
from bson.json_util import dumps
import uuid
import binascii

masterKey=''
IV = 16 * '\x41' #A in hex
paddedPassLen = 25


def main():
	while 1:
		option = raw_input('What would you like to do?\n1=View 2=Add 3=Exit\n')
		while (option !='1' and option !='2' and option !='3'):
			print 'not an option'
			option = raw_input('What would you like to do?\n1=View 2=Add 3=Exit\n')
		if option =='1':
			view();
		elif option =='2':
			add();
		elif option =='3':
			print 'terminating'
			exit()


def getSalt():
	return uuid.uuid4().hex

def hashMD5(salt):
	global masterKey
	return hashlib.md5(salt + masterKey).digest()

def hashSHA256(salt):
	global masterKey
	return hashlib.sha256(salt + masterKey).digest()

def hashBcrypt(salt):
	global masterKey
	return bcrypt.hashpw(masterKey, salt)



def hashtime(password):
	option = raw_input('which algorithm to hash key?\
		\n 1 = MD5\n 2 = SHA256\n 3 = BCRYPT\n')
	while (option != '1' and option != '2' and option !='3'):
		option = raw_input('enter [1, 2 or 3]\n')
	
	#salt=uuid.uuid4().hex
	global IV
	salt = getSalt()
	if option == '1':
		cipher = AES.new(hashMD5(salt), AES.MODE_CFB, IV)
	elif option =='2':
		cipher = AES.new(hashSHA256(salt), AES.MODE_CFB, IV)
	elif option== '3':
		salt=bcrypt.gensalt(12)
		key=hashBcrypt(salt)
		bkey=key.ljust(32)[:32]
		cipher = AES.new(bkey, AES.MODE_CFB, IV)
	paddedPass=pad(password)
	encryptedPass = bin(int(binascii.hexlify(cipher.encrypt(paddedPass)), 16))
	return option, encryptedPass, salt


def pad(password):
	global paddedPassLen 
	padding = paddedPassLen - len(password)
	
	for i in range(0,padding):
		password+='a'
		
	return password+str(padding)
	
def unpad(paddedPass):
	global paddedPassLen
	if paddedPass[-2:-1] == 'a':
		padding = paddedPass[-1:]
	else: 
		padding = paddedPass[-2:]
	x = paddedPassLen - int(padding)
	return paddedPass[0:x]


def countEntries():
	n=1
	numEntries=int(db.passwordEntries.count())
	while n<=numEntries:
		a=db.passwordEntries.find_one({'id': int(n)})
		if a == None:
			return n
		n+=1
	return n


def add():

	description = raw_input('enter a description (gmail, facebook...):')
	username = raw_input('enter a username:')
	temp = getpass.getpass('enter a password: ')
	if len(temp) > paddedPassLen:
		print 'max len is '+str(paddedPassLen)
		add();
		return
	password = getpass.getpass('please confirm your password:')
	if temp != password:
		print 'those did not match'
		add();
		return
	

	option = raw_input('\nis this correct?\n\n%s%s\n%s%s\n%s%s\n\n[y/n]\n'\
	 %('description:',description,'username:',username,'password:','********'))

	while (option != 'y' and option != 'n'):
		option = raw_input('enter [y or n]')
	if option =='y':
		hashAlgo, encryptedPassword, salt= hashtime(password);
		insert(description, username, encryptedPassword, hashAlgo, salt)
		print 'new password %s added' %description

		main();

	elif option=='n':
		print 'cancelled'
		add();



def decrypt(encryptedPassword, option, salt):
	global IV
	if option == '1':
		start=time.time()
		decipher = AES.new(hashMD5(salt), AES.MODE_CFB, IV)
		end=time.time()
	if option == '2':
		start=time.time()
		decipher = AES.new(hashSHA256(salt), AES.MODE_CFB, IV)
		end=time.time()
	if option =='3':
		key =hashBcrypt(salt)
		bkey=key.ljust(32)[:32]
		decipher = AES.new(bkey, AES.MODE_CFB, IV)
	a=binascii.unhexlify('%x' % int(encryptedPassword, 2))
	return unpad(decipher.decrypt(a))
	


def split(entry):
	key ="u\'password\': u\'" 
	before, key, after = entry.partition(key)
	key ="\'" 
	encryptedPassword, key, after = after.partition(key)
	
	key="option\': u\'"
	before, key, after = entry.partition(key)
	key="\'"
	decryptOption, key, after = after.partition(key)

	key="u\'salt\': u\'"
	before, key, after = entry.partition(key)
	key="\'"
	salt, key, after = after.partition(key)

	return encryptedPassword, decryptOption,salt

def view():
	
	docArray =[]
	for doc in db.passwordEntries.find({},{'id':1,'description':1, 'username':1, '_id':0}).sort('id', 1):
		docArray.append(dumps(doc))

		
	for doc in docArray:
		print doc
	option =raw_input('\nv=view password, m=modify, d=delete, b=back, e=exit\n')
	while (option != 'v' and option != 'm' and option != 'd' and option!='b' and option!='e'):
		option = raw_input('please enter a valid option\n')
	if option =='e':
		print 'exiting'
		exit(0)
	if option =='b':
		return
	if option =='v':
		try:
			option = int(raw_input('enter id of password to view[1,2,3...]\n'))
		except :
			print 'not a valid entry'
			return
		entry= db.passwordEntries.find_one({'id': option}, {'password':1,'_id':0, 'option':1, 'salt':1})
		encryptedPassword, decryptOption, salt = split(str(entry))
		password = decrypt(encryptedPassword, decryptOption, salt)

		print '\n'+password+'\n'
	if option =='d':
		try: 
			option = int(raw_input('enter id of password to delete[1,2,3...]\n'))
		except :
			print 'not a valid entry'
			return
		entry= dumps(db.passwordEntries.find_one({'id': option}, {'_id':0, 'description':1, 'username':1}))
		if entry =='null':
			print 'not a valid entry'
			return
		print entry
		confirm = raw_input('are you sure you want to delete this [y/n]\n')
		if confirm =='y':
			result = db.passwordEntries.delete_one({'id': option})
			print 'deleted'
		elif confirm=='n':
			return
		else: 
			print 'not a valid option'
			return

	if option == 'm':
		try:
			option = int(raw_input('enter id of password to modify[1,2,3...]\n'))
		except: 
			print 'not a valid entry'
			return
		entry= dumps(db.passwordEntries.find_one({'id': option}, {'_id':0, 'description':1, 'username':1}))
		if entry =='null':
			print 'not a valid entry'
			return
		print entry
		choice=raw_input('modify what?\np=password, d=description, u=username\n')
		if choice == 'd':
			description = raw_input('enter new description: ')
			result = db.passwordEntries.update({'id': option}, {'$set': {'description': description}})
			print 'successfully updated'
		elif choice == 'u':
			username = raw_input('enter new username: ')
			result = db.passwordEntries.update({'id': option}, {'$set': {'username': username}})
			print 'successfully updated'
		elif choice =='p':
			try: 
				hashAlgo, encryptedPass, salt = updatePass()
			except:
				return
			result = db.passwordEntries.update({'id': option}, {'$set': {'option': hashAlgo, 'password':encryptedPass, 'salt': salt}})
			print 'successfully updated'
		else :
			print 'not a valid entry'
			return
				
def updatePass():
	temp = getpass.getpass('enter a password: ')
	if len(temp) > paddedPassLen:
		print 'max len is '+str(paddedPassLen)
		return
	password = getpass.getpass('please confirm your password:')
	if temp != password:
		print 'those did not match'
		return
	return hashtime(password);


def insert(description,username,password,option,salt):
	result = db.passwordEntries.insert_one(
		{
			"id": countEntries(),
			"description": description,
			"username": username,
			"password": password,
			"option": option,
			"salt": salt
		})


def setupMaster():
	print 'we need to setup your master key'
	temp=getpass.getpass('Enter your new master key:')
	while len(temp)<7:
		print 'min len is 7'
		temp=getpass.getpass('Enter: your new master key:')
	password = getpass.getpass('please confirm:')
	if temp != password:
		print 'those did not match'
		exit(0)
	print 'successfully setup master key'
	return password

def authenticate():
	global masterKey
	storedVal=db.masterP.find_one({})
	if storedVal==None:
		salt=bcrypt.gensalt(12)
		key=hashBcrypt(salt)
		bkey=key.ljust(32)[:32]
		cipher = AES.new(bkey, AES.MODE_CFB, IV)
		paddedPass=pad(setupMaster())
		encryptedPass = bin(int(binascii.hexlify(cipher.encrypt(paddedPass)), 16))
		result = db.masterP.insert_one({
			"password": encryptedPass,
			"salt": salt
			})

	else: 
		
		key="password\': u\'"
		before, key, after = str(storedVal).partition(key)
		key="\'"
		encryptedMaster, key, after = after.partition(key)
		key="salt\': u\'"
		before, key, after = str(storedVal).partition(key)
		key="\'"
		salt, key, after = after.partition(key)

		attempt=getpass.getpass('Enter the master key:')
		key =hashBcrypt(salt)
		bkey=key.ljust(32)[:32]
		decipher = AES.new(bkey, AES.MODE_CFB, IV)


		
		print unpad(decipher.decrypt(binascii.unhexlify('%x' % int(encryptedMaster, 2))))
		if unpad(decipher.decrypt(binascii.unhexlify('%x' % int(encryptedMaster, 2)))) != attempt:
			print 'wrong'
			exit(0)
		else:
			masterKey=attempt
			main();




if __name__=='__main__':
	while 1:
		authenticate();
	
	
	

	