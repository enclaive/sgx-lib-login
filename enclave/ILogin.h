#include "enclave_t.h"
class ILogin {
	virtual void add_acc(user* usr) = 0;
	virtual void del_acc(user* usr) = 0;
	virtual void validate_login(user* usr) = 0;
};