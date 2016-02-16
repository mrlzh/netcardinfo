#ifndef __PCAPY_H__

extern "C" {
#ifdef WIN32
__declspec(dllexport)
#endif
void initpcapy(void);
}

extern PyObject* PcapError;

#endif
