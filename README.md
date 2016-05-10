# Clearent Hosted Payment Page Verification

Our Hosted Payment Page offers an additional layer of security, a signed response. This project is a Java example of how to verify our ECDSA signature returned on HPP response, to ensure that our response was not intercepted and modified.

## Requirements

- Java 8      - http://www.oracle.com/technetwork/java/javase/downloads/jdk8-downloads-2133151.html
- Maven       - http://maven.apache.org/download.cgi

## Implementation

You can see an example of how to implement signature verification in the ECDSASignature class.

## Test

You can see this in action by running our test ECDSASignatureTest by running the JUnit tests for this class. If you have maven configured you can run `mvn test` to run the tests from your command line.

## Usage

These lines in the test file represent the signed content to verify:

```
private static final String publicKey = "307a301406072a86410c03620......79e9759eac864df4fc781f466";
private static final String  message = "This is a test.";
private static final String  signature = "30650231008418584a5bb66f......eabb233a27dacfe3632ad6194";
```

In the real world your transaction response will look something like this (the signature will be much longer but shortened here for brevity):

{"code":"200","status":"success","exchange-id":"ID-CL3S4DrRGY01-cgw01-56931-1457859432339-0-813","links":[{"rel":"transaction","href":"/rest/v2/transactions?id=262246","id":"262246"}],"payload":**{"transaction":{"amount":"4.50","id":"262246","type":"SALE","result":"APPROVED","card":"XXXXXXXXXXXX1111","csc":"999","authorization-code":"TAS955","batch-string-id":"59","display-message":"Transaction approved","result-code":"000","exp-date":"1119"},"payloadType":"transaction"}**,"signature":"3064023045786078883"}

The part in bold is the message we need to verify:

```
// your actual public key provided by Clearent; same public key you used to run the transaction
private static final String publicKey = "307a301406072a86410c03620......79e9759eac864df4fc781f466";
// transaction response payload
private static final String  message = "{\"transaction\":{\"amount\":\"4.50\",\"id\":\"262246\",\"type\":\"SALE\",\"result\":\"APPROVED\",\"card\":\"XXXXXXXXXXXX1111\",\"csc\":\"999\",\"authorization-code\":\"TAS955\",\"batch-string-id\":\"59\",\"display-message\":\"Transaction approved\",\"result-code\":\"000\",\"exp-date\":\"1119\"},\"payloadType\":\"transaction\"}";
// actual signature from transaction
private static final String  signature = "3064023045786078883";
```

You can test any of your sandbox transactions using this method before migrating your code to your production server. Be aware that your sandbox and production public keys will be different.

## Additional Support

If you have any questions or need help integrating into your product, contact us at gatewaysales@clearent.com
