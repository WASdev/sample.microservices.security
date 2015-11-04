Work in progress

Attempting to show 3 approaches

Propagated Access Token

Signed JWT

API Key

Each approach has 3 projects

op - the open id connect provider server.
rp - the open id connect relying party. (Also known as 'the app', or 'the client')
rs - a microservice invoked by the app

Each project runs as its own standalone liberty configuration.

Ports have been selected to allow the 3 projects for each approach to coexist on a single host.


Note:

This is a first commit to establish project structure.. much is still yet to come / be adjusted. 
