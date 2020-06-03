# -*- Mode:python; c-file-style:"gnu"; indent-tabs-mode:nil -*- */
#
# Copyright (C) 2014-2019 Regents of the University of California.
# Author: Adeola Bannis <thecodemaiden@gmail.com>
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU Lesser General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Lesser General Public License for more details.
#
# You should have received a copy of the GNU Lesser General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.
# A copy of the GNU Lesser General Public License is in the file COPYING.

#####
# dump method taken from test_encode_decode_interest
#####
import unittest as ut
from pyndn import Name, Data, Sha256WithRsaSignature, DigestSha256Signature
from pyndn import Interest
from pyndn import KeyLocator, KeyLocatorType
from pyndn import InterestFilter
from pyndn.util import Blob
from pyndn.security import KeyChain
from pyndn.security.identity import IdentityManager
from pyndn.security.identity import MemoryIdentityStorage
from pyndn.security.identity import MemoryPrivateKeyStorage
from pyndn.security.policy import SelfVerifyPolicyManager

from test_utils import dump

# use Python 3's mock library if it's available
try:
    from unittest.mock import Mock
except ImportError:
    from mock import Mock

codedInterestNoSelectors = Blob(bytearray([
0x05, 0x12, # Interest
  0x07, 0x0A, 0x08, 0x03, 0x6E, 0x64, 0x6E, 0x08, 0x03, 0x61, 0x62, 0x63, # Name
  0x0A, 0x04, 0x61, 0x62, 0x61, 0x62   # Nonce
  ]))

simpleCodedInterestV03 = Blob(bytearray([
0x05, 0x07, # Interest
  0x07, 0x03, 0x08, 0x01, 0x49, # Name = /I
  0x12, 0x00, # MustBeFresh
  ]))

simpleCodedInterestV03Dump = [
  "name: /I",
  "canBeFresh: False",
  "mustBeFresh: True",
  "forwardingHint: <none>",
  "nonce: <none>",
  "lifetimeMilliseconds: <none>",
  "hopLimit: c8",
  "applicationParameters: <none>",
  "interestSignature: <none>"
  ]

"""
fullCodedInterestV03 = Blob(bytearray([
0x05, 0x29, # Interest
  0x07, 0x03, 0x08, 0x01, 0x49, # Name = /I
  0x21, 0x00, # CanBePrefix
  0x12, 0x00, # MustBeFresh
  0x1E, 0x0B, # ForwardingHint
    0x1F, 0x09, # Delegation
      0x1E, 0x02, 0x01, 0x00, # Preference = 256
      0x07, 0x03, 0x08, 0x01, 0x48, # Name = /H
  0x0A, 0x04, 0x12, 0x34, 0x56, 0x78, # Nonce
  0x0C, 0x02, 0x10, 0x00, # InterestLifetime = 4096
  0x22, 0x01, 0xD6, # HopLimit
  0x24, 0x04, 0xC0, 0xC1, 0xC2, 0xC3 # ApplicationParameters
  ]))
"""

fullCodedInterestV03 = Blob(bytearray([
    0x05, 0x29, # Interest
    0x07, 0x03, # Name
      0x08, 0x01, 0x49, # NameComponent
    #  0x02, 0x20, 0xFF, 0x91, 0x00, 0xE0, 0x4E, 0xAA, 0xDC, 0xF3, 0x06, 0x74, 0xD9, 0x80, 0x26, 0xA0, 0x51, 0xBA, 0x25, 0xF5, 0x6B, 0x69, 0xBF, 0xA0, 0x26, 0xDC, 0xCC, 0xD7, 0x2C, 0x6E, 0xA0, 0xF7, 0x31, 0x5A, # ParametersSha256DigestComponent
    0x21, 0x00, # CanBePrefix
    0x12, 0x00, # MustBeFresh
    0x1E, 0x0B, # ForwardingHint
      0x1F, 0x09, # Delegation
        0x1E, 0x02, 0x01, 0x00, # Preference = 256
        0x07, 0x03, 0x08, 0x01, 0x48, # Name = /H
    0x0A, 0x04, 0x12, 0x34, 0x56, 0x78, # Nonce
    0x0C, 0x02, 0x10, 0x00, # InterestLifetime = 4096
    0x22, 0x01, 0xD6, # HopLimit
    0x24, 0x04, 0xC0, 0xC1, 0xC2, 0xC3 # ApplicationParameters
    ]))

    # 05 4B    
    # 07 25
    # 08 01 49
    # 02 20 FF9100E04EAADCF30674D98026A051BA25F56B69BFA026DCCCD72C6EA0F7315A
    # 2100
    # 1200
    # 1E 0B 1F091E0201000703080148
    # 0A 04 12345678
    # 0C 02 1000
    # 22 01 D6
    # 24 04 C0C1C2C3
    
fullCodedInterestV03Dump = [
    "name: /I",
    "canBeFresh: True",
    "mustBeFresh: True",
    "forwardingHint:",
    "  Preference: 256, Name: /H",
    "nonce: 12345678",
    "lifetimeMilliseconds: 4096.0",
    "hopLimit: c8",
    "applicationParameters: c0c1c2c3",
    "interestSignature: <none>"
    ]

def dumpInterest(interest):
    result = []
    result.append(dump("name:", interest.getName().toUri()))
    
    result.append(dump("canBeFresh:", interest.getCanBePrefix()))
    
    result.append(dump("mustBeFresh:", interest.getMustBeFresh()))
    
    if interest.getForwardingHint().size() > 0:
        result.append(dump("forwardingHint:"))
        for i in range(interest.getForwardingHint().size()):
            result.append(dump("  Preference: " +
              str(interest.getForwardingHint().get(i).getPreference()) +
              ", Name: " +
              interest.getForwardingHint().get(i).getName().toUri()))
    else:
        result.append(dump("forwardingHint:", "<none>"))
        
    result.append(dump("nonce:", "<none>" if len(interest.getNonce()) == 0
                            else interest.getNonce().toHex()))
    result.append(dump("lifetimeMilliseconds:", 
        "<none>" if interest.getInterestLifetimeMilliseconds() is None
                  else interest.getInterestLifetimeMilliseconds()))
    result.append(dump("hopLimit:",
        "<none>" if interest.getHopLimit() is None
                  else format(interest.getHopLimit(), '02x')))
    if interest.getApplicationParameters() is not None:
        result.append(dump("applicationParameters:", 
        "<none>" if interest.getApplicationParameters().size() == 0
                  else interest.getApplicationParameters().toHex()))
        
        """
        InterestSignature = InterestSignatureInfo InterestSignatureValue
        
        InterestSignatureInfo = INTEREST-SIGNATURE-INFO-TYPE TLV-LENGTH
                                  SignatureType
                                  [KeyLocator]
                                  [SignatureNonce]
                                  [SignatureTime]
                                  [SignatureSeqNum]
        
        InterestSignatureValue = INTEREST-SIGNATURE-VALUE-TYPE TLV-LENGTH *OCTET
        """        
        result.append(dump("interestSignature: <none>"))

        """
        if interest.getKeyLocator().getType() is not None:
            if (interest.getKeyLocator().getType() ==
                KeyLocatorType.KEY_LOCATOR_DIGEST):
                result.append(dump("keyLocator: KeyLocatorDigest:",
                     interest.getKeyLocator().getKeyData().toHex()))
            elif interest.getKeyLocator().getType() == KeyLocatorType.KEYNAME:
                result.append(dump("keyLocator: KeyName:",
                     interest.getKeyLocator().getKeyName().toUri()))
            else:
                result.append(dump("keyLocator: <unrecognized KeyLocatorType"))
        else:
            result.append(dump("keyLocator: <none>"))
        """
    else:
        result.append(dump("applicationParameters: <none>"))
        
    return result

def interestDumpsEqual(dump1, dump2):
    # ignoring nonce, check that the dumped interests are equal
    unequal_set = set(dump1) ^ set(dump2)
    for s in unequal_set:
        if not s.startswith('nonce:'):
            return False
    return True

def createFreshInterest():
    freshInterest = (Interest(Name("/ndn/abc"))
      .setCanBePrefix(False)
      .setMustBeFresh(False)
      .setInterestLifetimeMilliseconds(30000)
      .setMustBeFresh(True))
    freshInterest.getForwardingHint().add(1, Name("/A"))

    return freshInterest

class TestInterestDump(ut.TestCase):
    def setUp(self):
        pass

    def test_no_selectors_must_be_fresh(self):
        interest = Interest()
        interest.wireDecode(codedInterestNoSelectors)
        self.assertEqual(False, interest.getMustBeFresh(),
          "MustBeFresh should be false if no selectors")

    def test_decode_v03_as_v02(self):
        interest1 = Interest()
        interest1.wireDecode(simpleCodedInterestV03)

        dump1 = dumpInterest(interest1)
        self.assertEqual(dump1, simpleCodedInterestV03Dump,
          "Decoded simpleCodedInterestV03 does not match the dump")

        interest2 = Interest()
        interest2.wireDecode(fullCodedInterestV03)

        dump2 = dumpInterest(interest2)
        self.assertEqual(dump2, fullCodedInterestV03Dump,
          "Decoded fullCodedInterestV03Dump does not match the dump")

class TestInterestMethods(ut.TestCase):
    def setUp(self):
        pass

    def test_empty_nonce(self):
        # make sure a freshly created interest has no nonce
        freshInterest = createFreshInterest()
        self.assertTrue(freshInterest.getNonce().isNull(), 'Freshly created interest should not have a nonce')

    def test_verify_digest_sha256(self):
        # Create a KeyChain but we don't need to add keys.
        identityStorage = MemoryIdentityStorage()
        keyChain = KeyChain(
          IdentityManager(identityStorage, MemoryPrivateKeyStorage()),
          SelfVerifyPolicyManager(identityStorage))

        interest = Interest(Name("/test/signed-interest"))
        keyChain.signWithSha256(interest)

        # We create 'mock' objects to replace callbacks since we're not
        # interested in the effect of the callbacks themselves.
        failedCallback = Mock()
        verifiedCallback = Mock()

        keyChain.verifyInterest(interest, verifiedCallback, failedCallback)
        self.assertEqual(failedCallback.call_count, 0, 'Signature verification failed')
        self.assertEqual(verifiedCallback.call_count, 1, 'Verification callback was not used.')

    def test_matches_data(self):
        interest = Interest(Name("/A"))
        interest.setCanBePrefix(False)

        # Check violating CanBePrefix.
        data = Data(Name("/A/D"))
        self.assertEqual(interest.matchesData(data), False)

        # Check violating PublisherPublicKeyLocator.
        data3 = Data(data)
        signature3 = Sha256WithRsaSignature()
        signature3.getKeyLocator().setType(KeyLocatorType.KEYNAME)
        signature3.getKeyLocator().setKeyName(Name("/G"))
        data3.setSignature(signature3)
        self.assertEqual(interest.matchesData(data3), False)

        # Do not test keylocator in interest packet
        #interest3 = Interest(interest)
        #interest3.getKeyLocator().setType(KeyLocatorType.KEYNAME)
        #interest3.getKeyLocator().setKeyName(Name("/G"))
        #self.assertEqual(interest3.matchesData(data3), True)

        data4 = Data(data)
        data4.setSignature(DigestSha256Signature())
        self.assertEqual(interest.matchesData(data4), False)

        # Do not test keylocator in interest packet
        #interest4 = Interest(interest)
        #interest4.setKeyLocator(KeyLocator())
        #self.assertEqual(interest4.matchesData(data4), True)

        # Check violating Exclude.
        data5 = Data(data)
        data5.setName(Name("/A/J"))
        self.assertEqual(interest.matchesData(data5), False)

        # Check violating Name.
        data6 = Data(data)
        data6.setName(Name("/H/I"))
        self.assertEqual(interest.matchesData(data6), False)

        data7 = Data(data)
        data7.setName(Name("/A/B"))

        interest7 = Interest(
          Name("/A/B/sha256digest=" +
               "54008e240a7eea2714a161dfddf0dd6ced223b3856e9da96792151e180f3b128"))
        self.assertEqual(interest7.matchesData(data7), True)

        # Check violating the implicit digest.
        interest7b = Interest(
          Name("/A/B/%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00" +
               "%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00"))
        self.assertEqual(interest7b.matchesData(data7), False)

        # Check excluding the implicit digest.
        interest8 = Interest(Name("/A/B"))
        interest8.getExclude().appendComponent(interest7.getName().get(2))
        self.assertEqual(interest8.matchesData(data7), False)

    def test_interest_filter_matching(self):
        self.assertEqual(True,  InterestFilter("/a").doesMatch(Name("/a/b")))
        self.assertEqual(True,  InterestFilter("/a/b").doesMatch(Name("/a/b")))
        self.assertEqual(False, InterestFilter("/a/b/c").doesMatch(Name("/a/b")))

        self.assertEqual(True,  InterestFilter("/a", "<b>").doesMatch(Name("/a/b")))
        self.assertEqual(False, InterestFilter("/a/b", "<b>").doesMatch(Name("/a/b")))

        self.assertEqual(False, InterestFilter("/a/b", "<c>").doesMatch(Name("/a/b/c/d")))
        self.assertEqual(False, InterestFilter("/a/b", "<b>").doesMatch(Name("/a/b/c/b")))
        self.assertEqual(True,  InterestFilter("/a/b", "<>*<b>").doesMatch(Name("/a/b/c/b")))

        self.assertEqual(False, InterestFilter("/a", "<b>").doesMatch(Name("/a/b/c/d")))
        self.assertEqual(True,  InterestFilter("/a", "<b><>*").doesMatch(Name("/a/b/c/d")))
        self.assertEqual(True,  InterestFilter("/a", "<b><>*").doesMatch(Name("/a/b")))
        self.assertEqual(False, InterestFilter("/a", "<b><>+").doesMatch(Name("/a/b")))
        self.assertEqual(True,  InterestFilter("/a", "<b><>+").doesMatch(Name("/a/b/c")))

    def test_set_application_parameters(self):
        interest = Interest("/ndn")
        self.assertTrue(not interest.hasApplicationParameters())
        applicationParameters = Blob(bytearray([ 0x23, 0x00 ]))
        interest.setApplicationParameters(applicationParameters)
        self.assertTrue(interest.hasApplicationParameters())
        self.assertTrue(interest.getApplicationParameters().equals
                        (applicationParameters))

        decodedInterest = Interest()
        decodedInterest.wireDecode(interest.wireEncode())
        self.assertTrue(decodedInterest.getApplicationParameters().equals
                        (applicationParameters))

        interest.setApplicationParameters(Blob())
        self.assertTrue(not interest.hasApplicationParameters())

    def test_append_parameters_digest(self):
        name = Name("/local/ndn/prefix")
        interest = Interest(name)

        self.assertTrue(not interest.hasApplicationParameters())
        # No parameters yet, so it should do nothing.
        interest.appendParametersDigestToName()
        self.assertEqual("/local/ndn/prefix", interest.getName().toUri())

        applicationParameters = Blob(bytearray([ 0x23, 0x01, 0xC0 ]))
        interest.setApplicationParameters(applicationParameters)
        self.assertTrue(interest.hasApplicationParameters())
        interest.appendParametersDigestToName()
        self.assertEqual(name.size() + 1, interest.getName().size())
        self.assertTrue(interest.getName().getPrefix(-1).equals(name))
        SHA256_LENGTH = 32
        self.assertEqual(SHA256_LENGTH, interest.getName().get(-1).getValue().size())
        
        self.assertEqual(interest.getName().toUri(), "/local/ndn/prefix/" +
          "params-sha256=a16cc669b4c9ef6801e1569488513f9523ffb28a39e53aa6e11add8d00a413fc")

if __name__ == '__main__':
    ut.main(verbosity=2)

