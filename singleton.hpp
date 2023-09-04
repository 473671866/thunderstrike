#pragma once

template <class _Ty>
class  Singleton
{
protected:
	Singleton() {}
public:
	virtual ~Singleton() {}

	static	_Ty* get_instance()
	{
		static _Ty instance;
		return &instance;
	}
};