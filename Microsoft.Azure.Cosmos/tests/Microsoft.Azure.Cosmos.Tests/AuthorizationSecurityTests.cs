//------------------------------------------------------------
// Copyright (c) Microsoft Corporation.  All rights reserved.
//------------------------------------------------------------

namespace Microsoft.Azure.Cosmos.Tests
{
    using System;
    using Microsoft.Azure.Documents;
    using Microsoft.VisualStudio.TestTools.UnitTesting;

    /// <summary>
    /// Additional security tests for authorization logic
    /// These tests validate edge cases and potential vulnerabilities found in PR review
    /// </summary>
    [TestClass]
    public class AuthorizationSecurityTests
    {
        [TestMethod]
        [ExpectedException(typeof(UnauthorizedException))]
        public void ParseAuthorizationToken_WithMalformedToken_ShouldThrowUnauthorizedException()
        {
            // Test malformed token that could cause index out of range
            string malformedToken = "type=master"; // Missing required parts
            
            AuthorizationHelper.ParseAuthorizationToken(
                malformedToken,
                out ReadOnlyMemory<char> type,
                out ReadOnlyMemory<char> version,
                out ReadOnlyMemory<char> token);
        }

        [TestMethod]
        [ExpectedException(typeof(UnauthorizedException))]
        public void ParseAuthorizationToken_WithIncompleteToken_ShouldThrowUnauthorizedException()
        {
            // Test token with only type and version, missing signature
            string incompleteToken = "type=master&ver=1.0"; // Missing sig part
            
            AuthorizationHelper.ParseAuthorizationToken(
                incompleteToken,
                out ReadOnlyMemory<char> type,
                out ReadOnlyMemory<char> version,
                out ReadOnlyMemory<char> token);
        }

        [TestMethod]
        [ExpectedException(typeof(UnauthorizedException))]
        public void ParseAuthorizationToken_WithEmptySignature_ShouldThrowUnauthorizedException()
        {
            // Test token with empty signature part
            string emptySignatureToken = "type=master&ver=1.0&sig=";
            
            AuthorizationHelper.ParseAuthorizationToken(
                emptySignatureToken,
                out ReadOnlyMemory<char> type,
                out ReadOnlyMemory<char> version,
                out ReadOnlyMemory<char> token);
        }

        [TestMethod]
        public void ParseAuthorizationToken_WithValidTokenAndComma_ShouldParseCorrectly()
        {
            // Test token with comma separator (as mentioned in code comments)
            string tokenWithComma = "type=master&ver=1.0&sig=validSignature,extraData";
            
            AuthorizationHelper.ParseAuthorizationToken(
                tokenWithComma,
                out ReadOnlyMemory<char> type,
                out ReadOnlyMemory<char> version,
                out ReadOnlyMemory<char> token);
                
            Assert.AreEqual("master", type.ToString());
            Assert.AreEqual("1.0", version.ToString());
            Assert.AreEqual("validSignature", token.ToString());
        }

        [TestMethod]
        [ExpectedException(typeof(UnauthorizedException))]
        public void ParseAuthorizationToken_WithNullToken_ShouldThrowUnauthorizedException()
        {
            AuthorizationHelper.ParseAuthorizationToken(
                null,
                out ReadOnlyMemory<char> type,
                out ReadOnlyMemory<char> version,
                out ReadOnlyMemory<char> token);
        }

        [TestMethod]
        [ExpectedException(typeof(UnauthorizedException))]
        public void ParseAuthorizationToken_WithEmptyToken_ShouldThrowUnauthorizedException()
        {
            AuthorizationHelper.ParseAuthorizationToken(
                "",
                out ReadOnlyMemory<char> type,
                out ReadOnlyMemory<char> version,
                out ReadOnlyMemory<char> token);
        }

        [TestMethod]
        public void ParseAuthorizationToken_WithUrlEncodedToken_ShouldDecodeCorrectly()
        {
            // Test URL encoded token to ensure proper decoding
            string urlEncodedToken = "type%3Dmaster%26ver%3D1.0%26sig%3DvalidSignature";
            
            AuthorizationHelper.ParseAuthorizationToken(
                urlEncodedToken,
                out ReadOnlyMemory<char> type,
                out ReadOnlyMemory<char> version,
                out ReadOnlyMemory<char> token);
                
            Assert.AreEqual("master", type.ToString());
            Assert.AreEqual("1.0", version.ToString());
            Assert.AreEqual("validSignature", token.ToString());
        }

        [TestMethod]
        public void TraceUnauthorized_WithMalformedToken_ShouldNotCrash()
        {
            // Test the potential index out of range vulnerability
            var provider = new AuthorizationTokenProviderMasterKey("VGhpcyBpcyBhIHNhbXBsZSBzdHJpbmc=");
            var exception = new DocumentClientException("Server used following string to sign", null, null);
            
            // These malformed tokens could cause crashes in the original code
            string[] malformedTokens = {
                "malformed",
                "type=master",
                "type=master&ver=1.0",
                "a&b",
                "type=master&ver=1.0&sig=", // Empty signature
                "type=master&ver=1.0&sig=abc", // Short signature
                ""
            };
            
            foreach (string malformedToken in malformedTokens)
            {
                try
                {
                    // This should not throw an unhandled exception
                    provider.TraceUnauthorized(exception, malformedToken, "test payload");
                    // If we get here without exception, the method handled the malformed token correctly
                    Assert.IsTrue(true, $"Successfully handled malformed token: {malformedToken}");
                }
                catch (IndexOutOfRangeException)
                {
                    Assert.Fail($"Index out of range exception occurred with token: {malformedToken}");
                }
                catch (Exception ex)
                {
                    // Other exceptions are acceptable as long as they're not IndexOutOfRangeException
                    Console.WriteLine($"Token '{malformedToken}' caused expected exception: {ex.GetType().Name}");
                }
            }
        }

        private string GenerateLongToken(string tokenType, int totalLength)
        {
            string prefix = $"type={tokenType}&ver=1.0&sig=";
            int signatureLength = totalLength - prefix.Length;
            if (signatureLength <= 0) signatureLength = 10;
            
            string signature = new string('a', signatureLength);
            return prefix + signature;
        }
    }
}