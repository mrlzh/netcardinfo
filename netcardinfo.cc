/*
 * Copyright (c) 2014 CORE Security Technologies
 *
 * This software is provided under under a slightly modified version
 * of the Apache Software License. See the accompanying LICENSE file
 * for more information.
 *
 */

#include <pcap.h>
#include <Python.h>

#include "netcardinfo.h"

PyObject *PcapError;

static PyObject*
findalldevs(PyObject *self, PyObject *args)
{
  char errbuff[PCAP_ERRBUF_SIZE];
  pcap_if_t *devs;

  int status = pcap_findalldevs(&devs, errbuff);
  if(status)
    {
      PyErr_SetString(PcapError, errbuff);
      return NULL;
    }

  if(devs==NULL)
    {
      PyErr_SetString(PcapError, "No valid interfaces to open");
      return NULL;
    }

  pcap_if_t *cursor = devs;
  PyObject* list = PyList_New(0);
  PyObject* onedevs;
  while(cursor)
    {
	onedevs = PyList_New(0);
	PyList_Append(onedevs, Py_BuildValue("s", cursor->name));
	PyList_Append(onedevs, Py_BuildValue("s", cursor->description));
      PyList_Append(list, onedevs);
      cursor = cursor->next;
    }

  pcap_freealldevs(devs);
  
  return list;
}

static PyMethodDef netcardinfo_methods[] = {
  {"findalldevs", findalldevs, METH_VARARGS, "findalldevs() lists all available interfaces"},
  {NULL, NULL}
};

static char *netcardinfo_doc =
"\nA wrapper for the Packet Capture (PCAP) library\n";

void
initnetcardinfo(void)
{
  PyObject *m, *d;


  m = Py_InitModule3("netcardinfo", netcardinfo_methods, netcardinfo_doc);

  /* Direct from pcap's net/bpf.h. */
  PyModule_AddIntConstant(m, "DLT_NULL", 0);
  PyModule_AddIntConstant(m, "DLT_EN10MB", 1);
  PyModule_AddIntConstant(m, "DLT_IEEE802", 6);
  PyModule_AddIntConstant(m, "DLT_ARCNET", 7);
  PyModule_AddIntConstant(m, "DLT_SLIP", 8);
  PyModule_AddIntConstant(m, "DLT_PPP", 9);
  PyModule_AddIntConstant(m, "DLT_FDDI", 10);
  PyModule_AddIntConstant(m, "DLT_ATM_RFC1483", 11);
  PyModule_AddIntConstant(m, "DLT_RAW", 12);
  PyModule_AddIntConstant(m, "DLT_PPP_SERIAL", 50);
  PyModule_AddIntConstant(m, "DLT_PPP_ETHER", 51);
  PyModule_AddIntConstant(m, "DLT_C_HDLC", 104);
  PyModule_AddIntConstant(m, "DLT_IEEE802_11", 105);
  PyModule_AddIntConstant(m, "DLT_LOOP", 108);
  PyModule_AddIntConstant(m, "DLT_LINUX_SLL", 113);
  PyModule_AddIntConstant(m, "DLT_LTALK", 114);

  d = PyModule_GetDict(m);
  PcapError = PyErr_NewException("netcardinfo.PcapError", NULL, NULL );
  if( PcapError )
    PyDict_SetItemString( d, "PcapError", PcapError );
}
