/*
 *      Copyright (C) 2016 Christian Browet
 *      http://xbmc.org
 *
 *  This Program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2, or (at your option)
 *  any later version.
 *
 *  This Program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with XBMC; see the file COPYING.  If not, see
 *  <http://www.gnu.org/licenses/>.
 *
 */

#include "NetworkInterface.h"
#include "InetAddress.h"
#include "Context.h"
#include "ContentResolver.h"
#include "Build.h"

#include "jutils-details.hpp"

using namespace jni;

const char* CJNINetworkInterface::m_classname = "java/net/NetworkInterface";

CJNINetworkInterface CJNINetworkInterface::getByName(const std::string& name)
{
  return CJNINetworkInterface(call_static_method<jhobject>(m_classname,
    "getByName", "(Ljava/lang/String;)Ljava/net/NetworkInterface;", jcast<jhstring>(name)));
}

CJNINetworkInterface CJNINetworkInterface::getByIndex(int index)
{
  return CJNINetworkInterface(call_static_method<jhobject>(m_classname,
    "getByIndex", "(I)Ljava/net/NetworkInterface;", index));
}

CJNINetworkInterface CJNINetworkInterface::getByInetAddress(const CJNIInetAddress& addr)
{
  return CJNINetworkInterface(call_static_method<jhobject>(m_classname,
    "getByInetAddress", "(Ljava/net/InetAddress;)Ljava/net/NetworkInterface;", addr.get_raw()));
}

std::string CJNINetworkInterface::getName() const
{
  return jcast<std::string>(call_method<jhstring>(m_object,
    "getName", "()Ljava/lang/String;"));
}

std::string CJNINetworkInterface::getDisplayName() const
{
  return jcast<std::string>(call_method<jhstring>(m_object,
    "getDisplayName", "()Ljava/lang/String;"));
}

std::vector<char> CJNINetworkInterface::getHardwareAddress() const
{
  JNIEnv *env = xbmc_jnienv();
  jhbyteArray array = call_method<jhbyteArray>(m_object,
    "getHardwareAddress", "()[B");

  std::vector<char> result;
  if (array.get())
  {
    jsize size = env->GetArrayLength(array.get());

    result.resize(size);
    env->GetByteArrayRegion(array.get(), 0, size, (jbyte*)result.data());
    
    // Check if this is a randomized/generic MAC address (02:00:00:00:00:00)
    // Android 10+ returns this for privacy reasons
    if (result.size() >= 6 && 
        result[0] == 0x02 && result[1] == 0x00 && 
        result[2] == 0x00 && result[3] == 0x00 &&
        result[4] == 0x00 && result[5] == 0x00)
    {
      // Generate a stable pseudo-MAC address based on Android_ID + device info
      try
      {
        // Get Android_ID from Settings.Secure
        jhclass settingsSecureClass = find_class("android/provider/Settings$Secure");
        if (settingsSecureClass.get())
        {
          CJNIContentResolver contentResolver = CJNIContext::getContentResolver();
          
          jmethodID getStringMethod = env->GetStaticMethodID(
            settingsSecureClass.get(),
            "getString",
            "(Landroid/content/ContentResolver;Ljava/lang/String;)Ljava/lang/String;"
          );
          
          jstring androidIdKey = env->NewStringUTF("android_id");
          jstring androidIdValue = (jstring)env->CallStaticObjectMethod(
            settingsSecureClass.get(),
            getStringMethod,
            contentResolver.get_raw().get(),
            androidIdKey
          );
          
          std::string androidId = "unknown";
          if (androidIdValue && !env->ExceptionCheck())
          {
            androidId = jcast<std::string>(jhstring(androidIdValue));
          }
          else
          {
            env->ExceptionClear();
          }
          
          if (androidIdKey)
            env->DeleteLocalRef(androidIdKey);
          if (androidIdValue)
            env->DeleteLocalRef(androidIdValue);
          
          // Create seed from Android_ID + manufacturer + model
          std::string seed = androidId + CJNIBuild::MANUFACTURER + CJNIBuild::MODEL;
          
          // Use MessageDigest to hash the seed to SHA-256
          jhclass messageDigestClass = find_class("java/security/MessageDigest");
          if (messageDigestClass.get())
          {
            jmethodID getInstanceMethod = env->GetStaticMethodID(
              messageDigestClass.get(),
              "getInstance",
              "(Ljava/lang/String;)Ljava/security/MessageDigest;"
            );
            
            jstring sha256Str = env->NewStringUTF("SHA-256");
            jobject digest = env->CallStaticObjectMethod(
              messageDigestClass.get(),
              getInstanceMethod,
              sha256Str
            );
            
            if (sha256Str)
              env->DeleteLocalRef(sha256Str);
            
            if (digest && !env->ExceptionCheck())
            {
              // Convert seed to byte array
              jstring seedString = env->NewStringUTF(seed.c_str());
              jclass stringClass = env->FindClass("java/lang/String");
              jmethodID getBytesMethod = env->GetMethodID(
                stringClass,
                "getBytes",
                "()[B"
              );
              jbyteArray seedBytes = (jbyteArray)env->CallObjectMethod(seedString, getBytesMethod);
              
              if (seedString)
                env->DeleteLocalRef(seedString);
              
              // Digest the seed
              jmethodID digestMethod = env->GetMethodID(
                messageDigestClass.get(),
                "digest",
                "([B)[B"
              );
              jbyteArray hashBytes = (jbyteArray)env->CallObjectMethod(digest, digestMethod, seedBytes);
              
              if (seedBytes)
                env->DeleteLocalRef(seedBytes);
              
              if (hashBytes && !env->ExceptionCheck())
              {
                // Take first 6 bytes for MAC address
                jsize hashSize = env->GetArrayLength(hashBytes);
                if (hashSize >= 6)
                {
                  result.resize(6);
                  env->GetByteArrayRegion(hashBytes, 0, 6, (jbyte*)result.data());
                  
                  // Mark as "locally administered" MAC address
                  // Set bit 1 (second LSB) and clear bit 0 (LSB) of first byte
                  result[0] = (result[0] & 0xFE) | 0x02;
                }
                
                env->DeleteLocalRef(hashBytes);
              }
              else
              {
                env->ExceptionClear();
              }
              
              env->DeleteLocalRef(digest);
            }
            else
            {
              env->ExceptionClear();
            }
          }
        }
      }
      catch (...)
      {
        // If pseudo-MAC generation fails, keep the original randomized MAC
      }
    }
  }

  return result;
}

int CJNINetworkInterface::getIndex() const
{
  return call_method<jboolean>(m_object,
    "getIndex", "()I");
}

int CJNINetworkInterface::getMTU() const
{
  return call_method<jboolean>(m_object,
    "getMTU", "()I");
}

bool CJNINetworkInterface::isLoopback() const
{
  return call_method<jboolean>(m_object,
    "isLoopback", "()Z");
}

bool CJNINetworkInterface::isPointToPoint() const
{
  return call_method<jboolean>(m_object,
    "isPointToPoint", "()Z");
}

bool CJNINetworkInterface::isUp() const
{
  return call_method<jboolean>(m_object,
    "isUp", "()Z");
}

bool CJNINetworkInterface::isVirtual() const
{
  return call_method<jboolean>(m_object,
    "isVirtual", "()Z");
}

bool CJNINetworkInterface::supportsMulticast() const
{
  return call_method<jboolean>(m_object,
    "supportsMulticast", "()Z");
}

bool CJNINetworkInterface::equals(const CJNINetworkInterface& other) const
{
  return call_method<jboolean>(m_object,
    "equals", "(Ljava/lang/Object;)Z", other.get_raw());
}

std::string CJNINetworkInterface::toString() const
{
  return jcast<std::string>(call_method<jhstring>(m_object,
    "toString", "()Ljava/lang/String;"));
}

