/*
 * Copyright 2016 OpenMarket Ltd
 * Copyright 2016 Vector Creations Ltd
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.matrix.olm;

import android.text.TextUtils;
import android.util.Log;

import java.util.Random;

/**
 * Olm SDK helper class.
 */
public class OlmUtility {
    private static final String LOG_TAG = "OlmUtility";

    public static final int RANDOM_KEY_SIZE = 32;
    public static final int RANDOM_RANGE = 256;

    /** Instance Id returned by JNI.
     * This value uniquely identifies this utility instance.
     **/
    private long mNativeId;

    public OlmUtility() {
        initUtility();
    }

    /**
     * Create a native utility instance.
     * To be called before any other API call.
     * @return true if init succeed, false otherwise.
     */
    private boolean initUtility() {
        mNativeId = initUtilityJni();
        return (0 != mNativeId);
    }

    private native long initUtilityJni();

    /**
     * Release native instance.<br>
     * Public API for {@link #releaseUtilityJni()}.
     */
    public void releaseUtility(){
        releaseUtilityJni();
        mNativeId = 0;
    }
    private native void releaseUtilityJni();

    /**
     * Verify an ed25519 signature.<br>
     * If the signature is verified, the method returns true. If false is returned, an error description is provided in aError.
     * If the key was too small, aError is set to "OLM.INVALID_BASE64".
     * If the signature was invalid, aError is set to "OLM.BAD_MESSAGE_MAC".<br>
     * @param aSignature the base64-encoded message signature to be checked.
     * @param aFingerprintKey the ed25519 key (fingerprint key)
     * @param aMessage the signed message
     * @param aError error message description
     * @return true if the signature is verified, false otherwise
     */
    public boolean verifyEd25519Signature(String aSignature, String aFingerprintKey, String aMessage, StringBuffer aError) {
        boolean retCode = false;
        String jniError;

        if (null == aError) {
            Log.e(LOG_TAG, "## verifyEd25519Signature(): invalid input error parameter");
        } else {
            aError.setLength(0);

            try {
                if (TextUtils.isEmpty(aSignature) || TextUtils.isEmpty(aFingerprintKey) || TextUtils.isEmpty(aMessage)) {
                    Log.e(LOG_TAG, "## verifyEd25519Signature(): invalid input parameters");
                    aError.append("JAVA sanity check failure - invalid input parameters");
                } else if (null == (jniError = verifyEd25519SignatureJni(aSignature.getBytes("UTF-8"), aFingerprintKey.getBytes("UTF-8"), aMessage.getBytes("UTF-8")))) {
                    retCode = true;
                } else {
                    aError.append(jniError);
                }
            } catch (Exception e) {
                Log.e(LOG_TAG, "## verifyEd25519Signature(): failed " + e.getMessage());
            }
        }

        return retCode;
    }

    /**
     * Verify an ed25519 signature.
     * Return a human readable error message in case of verification failure.
     * @param aSignature the base64-encoded message signature to be checked.
     * @param aFingerprintKey the ed25519 key
     * @param aMessage the signed message
     * @return null if validation succeed, the error message string if operation failed
     */
    private native String verifyEd25519SignatureJni(byte[] aSignature, byte[] aFingerprintKey, byte[] aMessage);


    /**
     * Compute the hash(SHA-256) value of the string given in parameter(aMessageToHash).<br>
     * The hash value is the returned by the method.
     * @param aMessageToHash message to be hashed
     * @return hash value if operation succeed, null otherwise
     */
     public String sha256(String aMessageToHash) {
        String hashRetValue = null;

         if (null != aMessageToHash) {
             try {
                 hashRetValue = sha256Jni(aMessageToHash.getBytes("UTF-8"));
             } catch (Exception e) {
                 Log.e(LOG_TAG, "## sha256(): failed " + e.getMessage());
             }
         }

        return hashRetValue;
    }

    private native String sha256Jni(byte[] aMessage);


    /**
     * Helper method to compute a string based on random integers.
     * @return string containing randoms integer values
     */
    public static String getRandomKey() {
        String keyRetValue;
        Random rand = new Random();
        StringBuilder strBuilder = new StringBuilder();

        for(int i = 0; i< RANDOM_KEY_SIZE; i++) {
            strBuilder.append(rand.nextInt(RANDOM_RANGE));
        }
        keyRetValue = strBuilder.toString();

        return keyRetValue;
    }

    /**
     * Return true the object resources have been released.<br>
     * @return true the object resources have been released
     */
    public boolean isReleased() {
        return (0 == mNativeId);
    }
}

