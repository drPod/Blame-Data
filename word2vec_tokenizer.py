import json
from gensim.models import Word2Vec
import os
import logging
import random
from constants import (
    TOKENIZED_BENIGN_COMMITS_DIR,
    TOKENIZED_VULN_INTRO_COMMITS_DIR,
    VECTOR_BENIGN_COMMITS_DIR,
    VECTOR_VULN_INTRO_COMMITS_DIR,
)
from constants import tokenization_loggingConfig
from ensure_directories import ensure_dirs

# Set up logging
tokenization_loggingConfig()
logger = logging.getLogger(__name__)


def get_random_json_files(directory, num_files=10000):
    all_json_files = []
    for root, dirs, files in os.walk(directory):
        json_files = [os.path.join(root, f) for f in files if f.endswith(".json")]
        all_json_files.append(json_files)

    total_files = sum(len(files) for files in all_json_files)
    if total_files <= num_files:
        logger.warning(
            f"Directory {directory} contains fewer than {num_files} JSON files. Using all available files."
        )
        return [file for sublist in all_json_files for file in sublist]

    selected_files = []
    while len(selected_files) < num_files:
        for subfolder_files in all_json_files:
            if subfolder_files and len(selected_files) < num_files:
                file = random.choice(subfolder_files)
                selected_files.append(file)
                subfolder_files.remove(file)

    return selected_files


def save_selected_files(files, output_file):
    with open(output_file, "w") as f:
        json.dump(files, f, indent=2)
    logger.info(f"Selected files list saved to {output_file}")


def load_tokens_from_json(file_path):
    try:
        with open(file_path, "r") as f:
            data = json.load(f)

        tokens = []
        if "file_changes" in data:
            for file_change in data["file_changes"].values():
                for change_type in ["added_lines", "removed_lines"]:
                    if change_type in file_change:
                        for line in file_change[change_type]:
                            tokens.append(line)

        return [token for token in tokens if token]
    except Exception as e:
        logger.error(f"Error loading tokens from {file_path}: {str(e)}")
        return []


def train_word2vec_model(sentences, vector_size=100, window=5, min_count=1):
    try:
        model = Word2Vec(
            vector_size=vector_size, window=window, min_count=min_count, workers=4
        )
        model.build_vocab(sentences)
        model.train(sentences, total_examples=model.corpus_count, epochs=model.epochs)
        return model
    except Exception as e:
        logger.error(f"Error training Word2Vec model: {str(e)}")
        return None


def tokens_to_vectors(model, tokens):
    vectors = {}
    try:
        for sentence in tokens:
            for token in sentence:
                if token in model.wv:
                    vectors[token] = model.wv[token].tolist()
        return vectors
    except Exception as e:
        logger.error(f"Error converting tokens to vectors: {str(e)}")
        return {}


def save_model(model, file_path):
    try:
        model.save(file_path)
        logger.info(f"Model saved to {file_path}")
    except Exception as e:
        logger.error(f"Error saving model to {file_path}: {str(e)}")


def load_model(file_path):
    try:
        return Word2Vec.load(file_path)
    except Exception as e:
        logger.error(f"Error loading model from {file_path}: {str(e)}")
        return None


def process_files(input_files, output_dir, model):
    file_count = len(input_files)
    processed = 0
    errors = 0

    for input_file in input_files:
        try:
            relative_path = os.path.relpath(input_file, os.path.dirname(output_dir))
            output_file = os.path.join(output_dir, relative_path)

            os.makedirs(os.path.dirname(output_file), exist_ok=True)

            tokens = load_tokens_from_json(input_file)
            vector_dict = tokens_to_vectors(model, tokens)

            with open(output_file, "w") as f:
                json.dump(vector_dict, f, indent=2)

            processed += 1
            if processed % 100 == 0:
                logger.info(f"Processed {processed}/{file_count} files")
        except Exception as e:
            logger.error(f"Error processing file {input_file}: {str(e)}")
            errors += 1

    logger.info(
        f"Finished processing {file_count} files. Successful: {processed}, Errors: {errors}"
    )


def main():
    try:
        ensure_dirs()
        model_file = "word2vec_model.model"

        benign_files = get_random_json_files(TOKENIZED_BENIGN_COMMITS_DIR)
        vuln_files = get_random_json_files(TOKENIZED_VULN_INTRO_COMMITS_DIR)

        # Save selected files to JSON
        save_selected_files(benign_files, "selected_benign_files.json")
        save_selected_files(vuln_files, "selected_vuln_files.json")

        if os.path.exists(model_file):
            logger.info(f"Loading existing model from {model_file}")
            model = load_model(model_file)
            if model is None:
                raise Exception("Failed to load existing model")
        else:
            all_sentences = []
            for input_files in [benign_files, vuln_files]:
                file_count = len(input_files)
                processed = 0

                for input_file in input_files:
                    try:
                        all_sentences.extend(load_tokens_from_json(input_file))

                        processed += 1
                        if processed % 1000 == 0:
                            logger.info(
                                f"Loaded tokens from {processed}/{file_count} files"
                            )
                    except Exception as e:
                        logger.error(f"Error processing file {input_file}: {str(e)}")

                logger.info(f"Finished loading tokens from {file_count} files")

            logger.info(f"Loaded {len(all_sentences)} sentences.")

            logger.info("Training Word2Vec model...")
            model = train_word2vec_model(all_sentences)
            if model is None:
                raise Exception("Failed to train Word2Vec model")

            logger.info("Saving the trained model...")
            save_model(model, model_file)

        logger.info("Processing benign commits...")
        process_files(benign_files, VECTOR_BENIGN_COMMITS_DIR, model)

        logger.info("Processing vulnerable commits...")
        process_files(vuln_files, VECTOR_VULN_INTRO_COMMITS_DIR, model)

    except Exception as e:
        logger.error(f"An error occurred in the main function: {str(e)}")


if __name__ == "__main__":
    main()
