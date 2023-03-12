from repository import Repository
from fuzzywuzzy import fuzz


class MapperService(object):
    def __init__(self, connection_string: str) -> None:
        self.connection_string = connection_string

    def run_unknown_mapper(self, similarity: float):
        fuzz_map = self._build_unknowns_map(similarity)
        print(f"Finished map job. Found {len(fuzz_map)} potential matches")
        for product in fuzz_map:
            print(f"{product[0]} -> {product[1]}")
        with Repository(self.connection_string) as r:
            r.clear_fuzzy_match_results()
            r.save_fuzzy_match_results(fuzz_map)

    def _build_unknowns_map(self, similarity: float):
        print('Started mapping')
        products = []
        unknown_products = []
        with Repository(self.connection_string) as r:
            products = r.get_products()
            unknown_products = r.get_unknown_products()

        fuzz_map = []
        for unknown_product in unknown_products:
            potential_matches = []
            for product in products:
                partial_ratio = fuzz.partial_ratio(unknown_product, product)
                ratio = fuzz.ratio(unknown_product, product)
                # print(f"compared {unknown_product} with {product}, similarity: {ratio}")
                if (ratio + partial_ratio) / 2 >= similarity and similarity / 2 < ratio and similarity / 2 < partial_ratio:
                    potential_matches.append({
                        "product": product,
                        "ratio": ratio,
                        "partial_ratio": partial_ratio
                    })
            # print(f"processed '{unknown_product}' product, found: {len(potential_matches)} potential matches")
            if len(potential_matches) > 0:
                fuzz_map.append((unknown_product, potential_matches))

        return fuzz_map
