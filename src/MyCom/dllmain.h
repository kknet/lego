// dllmain.h: 模块类的声明。

class CMyComModule : public ATL::CAtlDllModuleT< CMyComModule >
{
public :
	DECLARE_LIBID(LIBID_MyComLib)
	DECLARE_REGISTRY_APPID_RESOURCEID(IDR_MYCOM, "{3cf0adcb-2625-470b-9325-e93da573a0ab}")
};

extern class CMyComModule _AtlModule;
