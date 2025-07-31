import json
from util.logging import logger
from collections.abc import Iterable

def save_results_to_json(all_results, output_file):
    """
    saves result structure to json file
    all_results = list of PackageResult
    output_file = path to outfile
    """
    try:
        if isinstance(all_results, Iterable):
            all_results_dict = [pkgLibResult.to_dict() for pkgLibResult in all_results]
            with open(output_file, "w") as f:
                json.dump(all_results_dict, f, indent=4)
        else:
            with open(output_file, "w") as f:
                all_results_dict = [pkgLibResult.to_dict() for pkgLibResult in all_results]
                json.dump(all_results.to_dict(), f, indent=4)
    except Exception as e:
        logger.error(
            f"save_results_to_json exception: {e} type: {type(e).__name__}",
            exc_info=True,
        )