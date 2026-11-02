# Trained model artifact handoff

The supplied Module 5 notebook exports `group19_final_nids_random_forest_pipeline.joblib`, but the binary was not included with the uploaded source files for this packaging pass.

Generate the artifact from the NSL-KDD files by running `python train_model.py` from the repository root. The script writes the model, class mapping, actual evaluation JSON and SHA-256 checksum here.

Before a public release, verify the artifact loads in the target environment and that its measured metrics are consistent with the documented evaluation. Never load a `.joblib` file from an untrusted source. The sample CSV and the test double are not a substitute for this trained pipeline.
