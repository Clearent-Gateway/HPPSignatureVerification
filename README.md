# Clearent Hosted Payment Page Verification

Our Hosted Payment Page offers an additional layer of security, a signed response. This project is a Java example of how to verify our ECDSA signature returned on HPP response, to ensure that our response was not intercepted and modified.

## Requirements

- Java 8      - http://www.oracle.com/technetwork/java/javase/downloads/jdk8-downloads-2133151.html
- Maven       - http://maven.apache.org/download.cgi

## Implementation

You can see an example of how to implement signature verification in the ECDSASignature class.

## Test

You can see this in action by running our test ECDSASignatureTest by running the JUnit tests for this class. If you have maven configured you can run `mvn test` to run the tests from your command line.

## Additional Support

If you have any questions or need help integrating into your product, contact us at gatewaysales@clearent.com
