#include <stdio.h>
#include <string.h>
#include "chess.h"

static int failures = 0;
#define CHECK(cond, msg) do { if (!(cond)) { printf("FAIL: %s\n", msg); failures++; } } while (0)

static void mv(TTChess *g, const char *from, const char *to) {
    int fr, ff, tr, tf;
    tt_chess_parse_square(from, &fr, &ff);
    tt_chess_parse_square(to, &tr, &tf);
    if (!tt_chess_move(g, fr, ff, tr, tf))
        printf("  move %s->%s REJECTED\n", from, to);
}

/* clear the board, then place a piece */
static void clear(TTChess *g) {
    for (int r = 0; r < 8; r++)
        for (int f = 0; f < 8; f++) {
            g->board[r][f].type = TT_PIECE_NONE;
            g->board[r][f].color = TT_COLOR_WHITE;
        }
    g->white_ks = g->white_qs = g->black_ks = g->black_qs = false;
    g->ep_file = -1;
    g->status = TT_CHESS_PLAYING;
    g->winner = TT_COLOR_WHITE;
}

static void put(TTChess *g, const char *sq, TTPieceType t, TTColor c) {
    int r, f;
    tt_chess_parse_square(sq, &r, &f);
    g->board[r][f].type = t;
    g->board[r][f].color = c;
}

int main(void) {
    TTChess g;

    /* initial position */
    tt_chess_init(&g);
    int n = 0;
    for (int r = 0; r < 8; r++)
        for (int f = 0; f < 8; f++)
            if (g.board[r][f].type != TT_PIECE_NONE) n++;
    CHECK(n == 32, "initial position has 32 pieces");
    CHECK(g.to_move == TT_COLOR_WHITE, "white to move first");
    CHECK(!tt_chess_in_check(&g, TT_COLOR_WHITE), "no check at start");

    /* Scholar's mate */
    tt_chess_init(&g);
    mv(&g, "e2", "e4"); mv(&g, "e7", "e5");
    mv(&g, "f1", "c4"); mv(&g, "b8", "c6");
    mv(&g, "d1", "h5"); mv(&g, "g8", "f6");
    mv(&g, "h5", "f7");
    CHECK(g.status == TT_CHESS_CHECKMATE, "scholar's mate = checkmate");
    CHECK(g.winner == TT_COLOR_WHITE, "white wins scholar's mate");

    /* Fool's mate */
    tt_chess_init(&g);
    mv(&g, "f2", "f3"); mv(&g, "e7", "e5");
    mv(&g, "g2", "g4"); mv(&g, "d8", "h4");
    CHECK(g.status == TT_CHESS_CHECKMATE, "fool's mate = checkmate");
    CHECK(g.winner == TT_COLOR_BLACK, "black wins fool's mate");

    /* illegal moves */
    tt_chess_init(&g);
    CHECK(!tt_chess_move(&g, 1, 4, 0, 4), "white pawn can't move backward");
    CHECK(!tt_chess_move(&g, 1, 4, 4, 4), "pawn can't move 3 squares");
    CHECK(!tt_chess_move(&g, 6, 4, 5, 4), "can't move opponent's piece as white");

    /* en passant */
    tt_chess_init(&g);
    mv(&g, "e2", "e4"); mv(&g, "a7", "a6");
    mv(&g, "e4", "e5"); mv(&g, "d7", "d5");
    CHECK(g.ep_file == 3, "en passant target file = d");
    CHECK(tt_chess_move(&g, 4, 4, 5, 3), "en passant capture allowed");
    CHECK(g.board[5][3].type == TT_PIECE_PAWN, "white pawn now on d6");
    CHECK(g.board[4][4].type == TT_PIECE_NONE, "black pawn removed by ep");

    /* castling kingside */
    tt_chess_init(&g);
    mv(&g, "e2", "e4"); mv(&g, "e7", "e5");
    mv(&g, "g1", "f3"); mv(&g, "g8", "f6");
    mv(&g, "f1", "e2"); mv(&g, "f8", "e7");
    CHECK(tt_chess_move(&g, 0, 4, 0, 6), "white kingside castle allowed");
    CHECK(g.board[0][6].type == TT_PIECE_KING, "king on g1 after castle");
    CHECK(g.board[0][5].type == TT_PIECE_ROOK, "rook on f1 after castle");
    CHECK(!g.white_ks && !g.white_qs, "castling rights cleared after king move");

    /* castle through check is illegal: black bishop on a6 attacks f1 */
    tt_chess_init(&g);
    clear(&g);
    put(&g, "e1", TT_PIECE_KING, TT_COLOR_WHITE);
    put(&g, "h1", TT_PIECE_ROOK, TT_COLOR_WHITE);
    put(&g, "a6", TT_PIECE_BISHOP, TT_COLOR_BLACK);
    put(&g, "e8", TT_PIECE_KING, TT_COLOR_BLACK);
    g.to_move = TT_COLOR_WHITE;
    g.white_ks = true;
    CHECK(!tt_chess_move(&g, 0, 4, 0, 6), "castle through check is illegal");

    /* castle into check is illegal: black rook on g8 attacks g1 */
    tt_chess_init(&g);
    clear(&g);
    put(&g, "e1", TT_PIECE_KING, TT_COLOR_WHITE);
    put(&g, "h1", TT_PIECE_ROOK, TT_COLOR_WHITE);
    put(&g, "g8", TT_PIECE_ROOK, TT_COLOR_BLACK);
    put(&g, "e8", TT_PIECE_KING, TT_COLOR_BLACK);
    g.to_move = TT_COLOR_WHITE;
    g.white_ks = true;
    CHECK(!tt_chess_move(&g, 0, 4, 0, 6), "castle into check is illegal");

    /* promotion auto-queen: white pawn a7->a8 */
    tt_chess_init(&g);
    clear(&g);
    put(&g, "a7", TT_PIECE_PAWN, TT_COLOR_WHITE);
    put(&g, "e8", TT_PIECE_KING, TT_COLOR_BLACK);
    put(&g, "e1", TT_PIECE_KING, TT_COLOR_WHITE);
    g.to_move = TT_COLOR_WHITE;
    CHECK(tt_chess_move(&g, 6, 0, 7, 0), "pawn promotes");
    CHECK(g.board[7][0].type == TT_PIECE_QUEEN, "pawn auto-promotes to queen");
    CHECK(g.board[7][0].color == TT_COLOR_WHITE, "promoted queen is white");

    /* stalemate: black king a8, white king c6, white queen b6 (not check) */
    tt_chess_init(&g);
    clear(&g);
    put(&g, "a8", TT_PIECE_KING, TT_COLOR_BLACK);
    put(&g, "c6", TT_PIECE_KING, TT_COLOR_WHITE);
    put(&g, "b6", TT_PIECE_QUEEN, TT_COLOR_WHITE);
    g.to_move = TT_COLOR_BLACK;
    CHECK(!tt_chess_in_check(&g, TT_COLOR_BLACK), "black not in check (stalemate setup)");
    CHECK(!tt_chess_has_legal_move(&g, TT_COLOR_BLACK), "black has no legal move (stalemate)");

    /* checkmate: black king a8, white king c6, white queen b7 (check, no escape) */
    tt_chess_init(&g);
    clear(&g);
    put(&g, "a8", TT_PIECE_KING, TT_COLOR_BLACK);
    put(&g, "c6", TT_PIECE_KING, TT_COLOR_WHITE);
    put(&g, "b7", TT_PIECE_QUEEN, TT_COLOR_WHITE);
    g.to_move = TT_COLOR_BLACK;
    CHECK(tt_chess_in_check(&g, TT_COLOR_BLACK), "black in check (checkmate setup)");
    CHECK(!tt_chess_has_legal_move(&g, TT_COLOR_BLACK), "black has no legal move (checkmate)");

    /* a move that gives checkmate updates status */
    tt_chess_init(&g);
    clear(&g);
    put(&g, "a8", TT_PIECE_KING, TT_COLOR_BLACK);
    put(&g, "c6", TT_PIECE_KING, TT_COLOR_WHITE);
    put(&g, "b6", TT_PIECE_QUEEN, TT_COLOR_WHITE);
    g.to_move = TT_COLOR_WHITE;
    CHECK(tt_chess_move(&g, 5, 1, 6, 1), "Qb7 delivers checkmate");
    CHECK(g.status == TT_CHESS_CHECKMATE, "status = checkmate after Qb7");
    CHECK(g.winner == TT_COLOR_WHITE, "white wins");

    if (failures == 0) printf("ALL CHESS ENGINE TESTS PASSED\n");
    else printf("%d CHESS ENGINE TEST(S) FAILED\n", failures);
    return failures ? 1 : 0;
}
