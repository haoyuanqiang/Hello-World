#pragma once
#ifndef __ETHERNET_DRIVER__
#define __ETHERNET_DRIVER__
#include "pcap.h"
#include <Windows.h>
//-----------------------------------------------------------------------
//Name: CSLock
//Function: Use to enter a critical section and automatically 
//leave it when the object goes out of scope (including exceptions, etc).
//-----------------------------------------------------------------------
class NetLock
{
public:
   NetLock(CRITICAL_SECTION* lock)
      : pLock(lock) 
   {EnterCriticalSection(pLock);}

   ~NetLock()
    {LeaveCriticalSection(pLock);}

private:
   CRITICAL_SECTION* pLock;
};

//-----------------------------------------------------------------------
//Name:
//Function:
//-----------------------------------------------------------------------
class NetQueue
{
};

class NetControl
{};

class NetInterface
{};
#endif