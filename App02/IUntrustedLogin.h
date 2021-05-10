#pragma once
class IUntrustedLogin {
public:
	virtual void addUser(const char* username, const char* password) const = 0;
	virtual void delUser(const char* username) const = 0;
	virtual bool validateLogin(const char* username, const char* password) const = 0;
};