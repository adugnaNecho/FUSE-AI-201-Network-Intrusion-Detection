# Simulated Data and Dataset Statement

**Project:** Real-Time Network Intrusion Detection Using Machine Learning-Based Multi-Class Classification  
**Group:** Group 19 | FUSE AI-201

## Dataset used

Training and benchmark evaluation use public NSL-KDD files `KDDTrain+` and `KDDTest+`, obtained through KaggleHub (`hassan06/nslkdd`). The model uses 41 input features from labelled network connection records. This is public benchmark data, not a newly collected live traffic feed or data from a current operational organization.

## Synthetic data use

The repository includes a constructed illustrative sample CSV row for demonstrating the expected 41-feature input schema. This row is not claimed to be an observed network event. During model fitting, SMOTENC creates synthetic minority-class observations inside the training pipeline to address class imbalance. These synthetic observations are used for training only. The stratified validation split and independent `KDDTest+` records are not oversampled.

## Hosted demonstration

The hosted application is https://group19-network-intrusion-detection.streamlit.app/. The supplied screenshot shows a sample record uploaded to the interface and a DoS prediction with displayed maximum class probability 1.00 and severity High. This demonstrates the application interaction for that record only; it does not establish that the sample is a real attack, that the prediction is correct, or that the score is calibrated.

## Privacy and limitations

The project repository is not intended to contain private packet captures, customer traffic, credentials or personally identifying network records. Do not upload confidential traffic or sensitive network details to the public application. NSL-KDD is a historical benchmark and does not represent all current enterprise environments or establish reliable detection of modern/zero-day attacks. The application does not capture live packets or block traffic.

## Source and attribution

The training notebook uses KaggleHub dataset `hassan06/nslkdd`. A public NSL-KDD mirror is documented at https://github.com/jmnwong/NSL-KDD-Dataset. Original reference: M. Tavallaee, E. Bagheri, W. Lu and A. A. Ghorbani, “A Detailed Analysis of the KDD CUP 99 Data Set,” IEEE Symposium on Computational Intelligence for Security and Defense Applications, 2009. Raw benchmark files are not redistributed by this project; follow the dataset host's applicable terms.

## Declaration

This project uses public NSL-KDD benchmark records for training and evaluation, a constructed illustrative sample input for interface demonstration, and SMOTENC-generated synthetic minority observations during model fitting only. No model-performance claim in this submission is based on newly collected live operational traffic.
