
##### FIREWALL POLICY ATOMIZER is a framework designed to perform packet filtering firewall policy anomaly analysis and resolution, based on the formal concept of atomic predicates. This approach has the aim to simplify the anomaly management operations, make them efficient and solve all configuration anomalies.


## Installation
This framework requires the following dependencies to correctly work:
 - Java version 1.8 or higher (https://www.java.com/en/download/help/download_options.xml)
 - Apache Maven 3.6 (https://maven.apache.org/download.cgi)

## Usage
The framework can be launched from the Main class (/src/it/polito/verefoo/Main.java). The xml file describing the firewall policy configuration has to be specified as a parameter to the line 

	VerefooSerializer test = new VerefooSerializer((NFV) u.unmarshal(new FileInputStream("./MyConfigurationFile.xml")));

It must be compliant to the xsd schema specified in /xsd/nfvSchema.xsd.