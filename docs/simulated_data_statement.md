# Dataset and Synthetic Data Statement

This prototype uses the public NSL-KDD benchmark dataset, specifically the `KDDTrain+` and `KDDTest+` files retrieved in the Module 5 notebook through KaggleHub (`hassan06/nslkdd`). The benchmark contains labelled connection records and is not a live feed from a current operational network. No private organizational packet captures or personally identifying traffic data are included in this project package.

The dataset used for model training and evaluation is therefore **public benchmark data, not a wholly synthetic dataset**. The sample CSV distributed with this repository is a constructed illustrative input row used to demonstrate the expected 41-feature interface; it is not presented as an independently observed network event.

The training pipeline uses SMOTENC to synthesize additional minority-class training examples. Those synthetic samples are generated only inside the training workflow and are not added to the validation or official test sets. Their use is disclosed because model fitting therefore includes synthetic training observations.

The benchmark's age and known distribution limitations mean its results do not establish that the model can detect modern, previously unseen or live network attacks. Consult and comply with the dataset host's terms and the original dataset's citation/usage requirements before redistribution. The raw dataset files are intentionally not included in this repository.
