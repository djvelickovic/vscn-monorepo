from repository import Repository
from fuzzywuzzy import fuzz


class MapperService(object):
    def __init__(self, connection_string: str) -> None:
        self.connection_string = connection_string

    def run_unknown_mapper(self, similarity: float):
        fuzz_map = self._build_unknowns_map(similarity)
        print(f"Finished map job. Found {len(fuzz_map)} potential matches")
        
        with Repository(self.connection_string) as r:
            r.clear_fuzzy_match_results()
            if len(fuzz_map) > 0:
                r.save_fuzzy_match_results(fuzz_map)

    def _build_unknowns_map(self, similarity: float):
        print('Started mapping')
        product_names = []
        unmatched_dependencies = []
        with Repository(self.connection_string) as r:
            product_names = r.get_products()
            unmatched_dependencies = r.get_unmatched_dependencies()

        fuzz_map = []
        for idx, unmatched_dependency in enumerate(unmatched_dependencies):
            dependency_name = unmatched_dependency["dependency_name"]
            language = unmatched_dependency["language"]
            
            potential_matches = []
            for product in product_names:
                partial_ratio = fuzz.partial_ratio(dependency_name, product)
                ratio = fuzz.ratio(dependency_name, product)
                # print(f"compared {unmatched_dependency} with {product}, similarity: {ratio}")
                if (ratio + partial_ratio) / 2 >= similarity and (ratio >= similarity / 2 and partial_ratio >= similarity / 2) :
                    potential_matches.append({
                        "product": product,
                        "ratio": ratio,
                        "partial_ratio": partial_ratio
                    })

            print(f"({idx}/{len(unmatched_dependencies)}) processed '{dependency_name}' product, found: {len(potential_matches)} potential matches")
            
            if len(potential_matches) > 0:
                fuzz_map.append((dependency_name, language, potential_matches))

        return fuzz_map
