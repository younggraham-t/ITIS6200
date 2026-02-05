import hashlib

student_identity_paramaters = "801118969-Graham-9Tlue"

print()
print("Starting String: " + student_identity_paramaters)
print()
print()
print("MD5 Hash: " + hashlib.md5(student_identity_paramaters.encode('utf-8')).hexdigest())
print()
