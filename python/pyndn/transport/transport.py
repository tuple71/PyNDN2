# -*- Mode:python; c-file-style:"gnu"; indent-tabs-mode:nil -*- */
#
# Copyright (C) 2014 Regents of the University of California.
# Author: Jeff Thompson <jefft0@remap.ucla.edu>
# See COPYING for copyright and distribution information.
#

"""
This module defines the Transport class which is a base class for specific
transport classes such as UnixTransport.
"""

class Transport(object):
    class ConnectionInfo(object):
        """
        A Transport.ConnectionInfo is a base class for connection information 
        used by subclasses of Transport.
        """
        pass
    
    def connect(self, connectionInfo, elementListener):
        """
        Connect according to the info in ConnectionInfo, and use 
        elementListener.
        
        :param connectionInfo: An object of a subclass of ConnectionInfo.
        :type connectionInfo: A subclass of ConnectionInfo
        :param elementListener: The elementListener must remain valid during the 
          life of this object.
        :type elementListener: An object with onReceivedData
        :raises: RuntimeError for unimplemented if the derived class does not 
          override.
        """
        raise RuntimeError("connect is not implemented")
    
    def send(self, data):
        """
        Set data to the host.
        
        :param data: The buffer of data to send.
        :type data: An array type.
        :raises: RuntimeError for unimplemented if the derived class does not 
          override.
        """
        raise RuntimeError("send is not implemented")

    def processEvents(self):
        """
        Process any data to receive.  For each element received, call 
        elementListener.onReceivedElement.
        This is non-blocking and will silently time out after a brief period if 
        there is no data to receive.
        You should repeatedly call this from an event loop.
        You should normally not call this directly since it is called by 
        Face.processEvents.
        If you call this from an main event loop, you may want to catch and 
        log/disregard all exceptions.

        :raises: RuntimeError for unimplemented if the derived class does not 
          override.
        """
        raise RuntimeError("processEvents is not implemented")

    def getIsConnected(self):
        """
        Check if the transport is connected.
        
        :return: True if connected.
        :rtype: bool
        :raises: RuntimeError for unimplemented if the derived class does not 
          override.
        """
        raise RuntimeError("getIsConnected is not implemented")

    def close(self):
        """
        Close the connection.  This base class implementation does nothing, but 
          your derived class can override.
        """
        pass
    