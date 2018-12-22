<p>Simple JAVA-8 project which generates valid signed HTTP requests for the Satispay API inStore API.</p>
<p>The project includes test cases for each HTTP request (GET, POST, PUT, DELETE)</p>
<p>The class responsible for signing the HTTP request is the SignatureBuilder. It receives a bunch of headers, the signing-key and the request target and builds the Signature string using the provided private key.</p>
<p>In order to build the project and run the tests maven is necessary. Simply run </p><code>mvn test</code>