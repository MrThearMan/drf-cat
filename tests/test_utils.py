from cat_service.utils import as_human_readable_list, snake_case_to_header_case


def test_as_human_readable_list():
    assert as_human_readable_list([]) == ""
    assert as_human_readable_list(["a"]) == "'a'"
    assert as_human_readable_list(["a", "b"]) == "'a' & 'b'"
    assert as_human_readable_list(["a", "b", "c"]) == "'a', 'b' & 'c'"
    assert as_human_readable_list(["a", "b", "c"], last_sep="and") == "'a', 'b' and 'c'"
    assert as_human_readable_list(i for i in ["a"]) == "'a'"
    assert as_human_readable_list(i for i in ["a", "b"]) == "'a' & 'b'"
    assert as_human_readable_list(i for i in ["a", "b", "c"]) == "'a', 'b' & 'c'"
    assert as_human_readable_list((i for i in ["a", "b", "c"]), last_sep="or") == "'a', 'b' or 'c'"


def test_snake_case_to_header_case():
    assert snake_case_to_header_case("") == ""
    assert snake_case_to_header_case("snake") == "Snake"
    assert snake_case_to_header_case("snake_case") != "snake_case"
    assert snake_case_to_header_case("snake_case_longer") == "Snake-Case-Longer"
