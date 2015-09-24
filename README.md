# PrimoNormalizationRules
Converts PRIMO normalization XML into a DSL or a CSV file

__This is very old code and it was made organically(trial and error).__

Download the Normalization rules from the Back Office server and store them in the pipes directory.

* Normalization Rules are located in CUSTOMER directory on the Back office.
```js
  be_pipes
  cd CUSTOMER
```

* The CUSTOMER directory contains directories that should mirror the Back Office 'Pipes' list
 __File you need to download__
```js
  tar zcvf /tmp/my_rules.tgz ./MyPipe/conf/rules.conf
  scp user@my.primo.back.office.server:/tmp/my_rules.tgz ./pipes
```  

* Extract the rules and run the script
```js
  tar zxvf my_rules.tgz
  ./bin/nm_rules_2_csv.rb MyPipe
```  
