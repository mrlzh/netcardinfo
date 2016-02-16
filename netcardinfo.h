#ifndef __PCAPY_H__

extern "C" {
#ifdef WIN32
__declspec(dllexport)
#endif
void initnetcardinfo(void);
}

extern PyObject* PcapError;

#endif
