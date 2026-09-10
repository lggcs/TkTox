#include "chess.h"

#include <string.h>

/* Board layout: board[rank][file]. rank 0 = rank 1 (white back rank),
   rank 7 = rank 8. file 0 = 'a', file 7 = 'h'. */

static void set_piece(TTChess *g, int rank, int file, TTPieceType type, TTColor color) {
    g->board[rank][file].type = type;
    g->board[rank][file].color = color;
}

void tt_chess_init(TTChess *g) {
    memset(g, 0, sizeof *g);
    g->to_move = TT_COLOR_WHITE;
    g->ep_file = -1;
    g->status = TT_CHESS_PLAYING;

    /* back ranks */
    const TTPieceType back[TT_CHESS_FILES] = {
        TT_PIECE_ROOK, TT_PIECE_KNIGHT, TT_PIECE_BISHOP, TT_PIECE_QUEEN,
        TT_PIECE_KING, TT_PIECE_BISHOP, TT_PIECE_KNIGHT, TT_PIECE_ROOK,
    };
    for (int f = 0; f < TT_CHESS_FILES; f++) {
        set_piece(g, 0, f, back[f], TT_COLOR_WHITE);
        set_piece(g, 1, f, TT_PIECE_PAWN, TT_COLOR_WHITE);
        set_piece(g, 6, f, TT_PIECE_PAWN, TT_COLOR_BLACK);
        set_piece(g, 7, f, back[f], TT_COLOR_BLACK);
    }
    g->white_ks = g->white_qs = true;
    g->black_ks = g->black_qs = true;
}

bool tt_chess_parse_square(const char *s, int *rank, int *file) {
    if (!s || s[0] < 'a' || s[0] > 'h' || s[1] < '1' || s[1] > '8' || s[2] != '\0')
        return false;
    *file = s[0] - 'a';
    *rank = s[1] - '1';
    return true;
}

void tt_chess_format_square(int rank, int file, char out[3]) {
    out[0] = (char)('a' + file);
    out[1] = (char)('1' + rank);
    out[2] = '\0';
}

static bool in_bounds(int rank, int file) {
    return rank >= 0 && rank < TT_CHESS_RANKS && file >= 0 && file < TT_CHESS_FILES;
}

/* Is (rank,file) attacked by any piece of color `by`? */
bool tt_chess_square_attacked(const TTChess *g, int rank, int file, TTColor by) {
    /* pawn attacks */
    int pr = (by == TT_COLOR_WHITE) ? rank - 1 : rank + 1;
    if (in_bounds(pr, file - 1) && g->board[pr][file - 1].type == TT_PIECE_PAWN &&
        g->board[pr][file - 1].color == by)
        return true;
    if (in_bounds(pr, file + 1) && g->board[pr][file + 1].type == TT_PIECE_PAWN &&
        g->board[pr][file + 1].color == by)
        return true;

    /* knight */
    static const int kd[8][2] = {{-2,-1},{-2,1},{2,-1},{2,1},{-1,-2},{-1,2},{1,-2},{1,2}};
    for (int i = 0; i < 8; i++) {
        int r = rank + kd[i][0], f = file + kd[i][1];
        if (in_bounds(r, f) && g->board[r][f].type == TT_PIECE_KNIGHT &&
            g->board[r][f].color == by)
            return true;
    }

    /* king */
    for (int dr = -1; dr <= 1; dr++)
        for (int df = -1; df <= 1; df++) {
            if (dr == 0 && df == 0) continue;
            int r = rank + dr, f = file + df;
            if (in_bounds(r, f) && g->board[r][f].type == TT_PIECE_KING &&
                g->board[r][f].color == by)
                return true;
        }

    /* sliding: rook/queen (orthogonal), bishop/queen (diagonal) */
    static const int dirs[4][2] = {{1,0},{-1,0},{0,1},{0,-1}};
    for (int i = 0; i < 4; i++) {
        int r = rank + dirs[i][0], f = file + dirs[i][1];
        while (in_bounds(r, f)) {
            TTPiece p = g->board[r][f];
            if (p.type != TT_PIECE_NONE) {
                if (p.color == by && (p.type == TT_PIECE_ROOK || p.type == TT_PIECE_QUEEN))
                    return true;
                break;
            }
            r += dirs[i][0];
            f += dirs[i][1];
        }
    }
    static const int ddirs[4][2] = {{1,1},{1,-1},{-1,1},{-1,-1}};
    for (int i = 0; i < 4; i++) {
        int r = rank + ddirs[i][0], f = file + ddirs[i][1];
        while (in_bounds(r, f)) {
            TTPiece p = g->board[r][f];
            if (p.type != TT_PIECE_NONE) {
                if (p.color == by && (p.type == TT_PIECE_BISHOP || p.type == TT_PIECE_QUEEN))
                    return true;
                break;
            }
            r += ddirs[i][0];
            f += ddirs[i][1];
        }
    }
    return false;
}

bool tt_chess_in_check(const TTChess *g, TTColor color) {
    /* find the king */
    for (int r = 0; r < TT_CHESS_RANKS; r++)
        for (int f = 0; f < TT_CHESS_FILES; f++)
            if (g->board[r][f].type == TT_PIECE_KING && g->board[r][f].color == color)
                return tt_chess_square_attacked(g, r, f, color == TT_COLOR_WHITE ? TT_COLOR_BLACK : TT_COLOR_WHITE);
    return false; /* no king (shouldn't happen) */
}

/* Does the move from->to (already validated as a pseudo-legal piece move)
   leave the mover's own king in check? */
static bool move_leaves_self_in_check(const TTChess *g, int fr, int ff, int tr, int tf) {
    TTChess tmp = *g;
    TTPiece captured = tmp.board[tr][tf];
    tmp.board[tr][tf] = tmp.board[fr][ff];
    tmp.board[fr][ff].type = TT_PIECE_NONE;
    tmp.board[fr][ff].color = TT_COLOR_WHITE;
    bool check = tt_chess_in_check(&tmp, tmp.board[tr][tf].color);
    (void)captured;
    return check;
}

/* Generate a pseudo-legal move list for the side to move. Returns count.
   Each move is packed as (from_rank<<12)|(from_file<<9)|(to_rank<<6)|(to_file<<3)|(promo?1:0).
   We only need to know whether ANY legal move exists, so we stop early. */
static bool has_any_legal_move(const TTChess *g, TTColor color) {
    for (int fr = 0; fr < TT_CHESS_RANKS; fr++) {
        for (int ff = 0; ff < TT_CHESS_FILES; ff++) {
            TTPiece p = g->board[fr][ff];
            if (p.type == TT_PIECE_NONE || p.color != color) continue;

            /* pawn */
            if (p.type == TT_PIECE_PAWN) {
                int dir = (color == TT_COLOR_WHITE) ? 1 : -1;
                int start = (color == TT_COLOR_WHITE) ? 1 : 6;
                int tr = fr + dir;
                if (in_bounds(tr, ff) && g->board[tr][ff].type == TT_PIECE_NONE) {
                    if (!move_leaves_self_in_check(g, fr, ff, tr, ff)) return true;
                    if (fr == start) {
                        int tr2 = fr + 2 * dir;
                        if (g->board[tr2][ff].type == TT_PIECE_NONE &&
                            !move_leaves_self_in_check(g, fr, ff, tr2, ff))
                            return true;
                    }
                }
                for (int df = -1; df <= 1; df += 2) {
                    int tf = ff + df;
                    if (!in_bounds(tr, tf)) continue;
                    TTPiece t = g->board[tr][tf];
                    if (t.type != TT_PIECE_NONE && t.color != color) {
                        if (!move_leaves_self_in_check(g, fr, ff, tr, tf)) return true;
                    } else if (t.type == TT_PIECE_NONE && tf == g->ep_file && tr == (color == TT_COLOR_WHITE ? 5 : 2)) {
                        /* en passant */
                        if (!move_leaves_self_in_check(g, fr, ff, tr, tf)) return true;
                    }
                }
                continue;
            }

            /* knight */
            if (p.type == TT_PIECE_KNIGHT) {
                static const int kd[8][2] = {{-2,-1},{-2,1},{2,-1},{2,1},{-1,-2},{-1,2},{1,-2},{1,2}};
                for (int i = 0; i < 8; i++) {
                    int tr = fr + kd[i][0], tf = ff + kd[i][1];
                    if (!in_bounds(tr, tf)) continue;
                    TTPiece t = g->board[tr][tf];
                    if (t.type != TT_PIECE_NONE && t.color == color) continue;
                    if (!move_leaves_self_in_check(g, fr, ff, tr, tf)) return true;
                }
                continue;
            }

            /* king */
            if (p.type == TT_PIECE_KING) {
                for (int dr = -1; dr <= 1; dr++)
                    for (int df = -1; df <= 1; df++) {
                        if (dr == 0 && df == 0) continue;
                        int tr = fr + dr, tf = ff + df;
                        if (!in_bounds(tr, tf)) continue;
                        TTPiece t = g->board[tr][tf];
                        if (t.type != TT_PIECE_NONE && t.color == color) continue;
                        if (!move_leaves_self_in_check(g, fr, ff, tr, tf)) return true;
                    }
                continue;
            }

            /* sliding pieces */
            int dirs[4][2] = {{1,0},{-1,0},{0,1},{0,-1}};
            int ddirs[4][2] = {{1,1},{1,-1},{-1,1},{-1,-1}};
            int (*sets)[2] = NULL;
            int n = 0;
            if (p.type == TT_PIECE_ROOK) { sets = dirs; n = 4; }
            else if (p.type == TT_PIECE_BISHOP) { sets = ddirs; n = 4; }
            else if (p.type == TT_PIECE_QUEEN) { sets = dirs; n = 4; }
            if (p.type == TT_PIECE_QUEEN) {
                /* queen = rook + bishop */
                for (int i = 0; i < 4; i++) {
                    int tr = fr + ddirs[i][0], tf = ff + ddirs[i][1];
                    while (in_bounds(tr, tf)) {
                        TTPiece t = g->board[tr][tf];
                        if (t.type != TT_PIECE_NONE && t.color == color) break;
                        if (!move_leaves_self_in_check(g, fr, ff, tr, tf)) return true;
                        if (t.type != TT_PIECE_NONE) break;
                        tr += ddirs[i][0];
                        tf += ddirs[i][1];
                    }
                }
            }
            if (sets) {
                for (int i = 0; i < n; i++) {
                    int tr = fr + sets[i][0], tf = ff + sets[i][1];
                    while (in_bounds(tr, tf)) {
                        TTPiece t = g->board[tr][tf];
                        if (t.type != TT_PIECE_NONE && t.color == color) break;
                        if (!move_leaves_self_in_check(g, fr, ff, tr, tf)) return true;
                        if (t.type != TT_PIECE_NONE) break;
                        tr += sets[i][0];
                        tf += sets[i][1];
                    }
                }
            }
        }
    }
    return false;
}

bool tt_chess_has_legal_move(const TTChess *g, TTColor color) {
    return has_any_legal_move(g, color);
}

bool tt_chess_move(TTChess *g, int from_rank, int from_file,
                   int to_rank, int to_file) {
    if (!in_bounds(from_rank, from_file) || !in_bounds(to_rank, to_file))
        return false;
    TTPiece p = g->board[from_rank][from_file];
    if (p.type == TT_PIECE_NONE || p.color != g->to_move)
        return false;
    TTPiece t = g->board[to_rank][to_file];
    if (t.type != TT_PIECE_NONE && t.color == p.color)
        return false;

    /* validate the move is pseudo-legal for the piece type */
    bool legal = false;
    int dr = to_rank - from_rank, df = to_file - from_file;

    if (p.type == TT_PIECE_PAWN) {
        int dir = (p.color == TT_COLOR_WHITE) ? 1 : -1;
        int start = (p.color == TT_COLOR_WHITE) ? 1 : 6;
        if (df == 0 && t.type == TT_PIECE_NONE) {
            if (dr == dir) legal = true;
            else if (dr == 2 * dir && from_rank == start &&
                     g->board[from_rank + dir][from_file].type == TT_PIECE_NONE)
                legal = true;
        } else if (df == 1 || df == -1) {
            if (dr == dir) {
                if (t.type != TT_PIECE_NONE) legal = true;
                else if (to_rank == (p.color == TT_COLOR_WHITE ? 5 : 2) &&
                         to_file == g->ep_file)
                    legal = true; /* en passant */
            }
        }
    } else if (p.type == TT_PIECE_KNIGHT) {
        if ((dr == 2 && df == 1) || (dr == 2 && df == -1) ||
            (dr == -2 && df == 1) || (dr == -2 && df == -1) ||
            (dr == 1 && df == 2) || (dr == 1 && df == -2) ||
            (dr == -1 && df == 2) || (dr == -1 && df == -2))
            legal = true;
    } else if (p.type == TT_PIECE_KING) {
        if (dr >= -1 && dr <= 1 && df >= -1 && df <= 1 && (dr || df))
            legal = true;
        else if (dr == 0 && df == 2) { /* kingside castle */
            bool ks = (p.color == TT_COLOR_WHITE) ? g->white_ks : g->black_ks;
            int r = from_rank;
            if (ks && g->board[r][5].type == TT_PIECE_NONE &&
                g->board[r][6].type == TT_PIECE_NONE &&
                g->board[r][7].type == TT_PIECE_ROOK &&
                g->board[r][7].color == p.color &&
                !tt_chess_square_attacked(g, r, 4, p.color == TT_COLOR_WHITE ? TT_COLOR_BLACK : TT_COLOR_WHITE) &&
                !tt_chess_square_attacked(g, r, 5, p.color == TT_COLOR_WHITE ? TT_COLOR_BLACK : TT_COLOR_WHITE) &&
                !tt_chess_square_attacked(g, r, 6, p.color == TT_COLOR_WHITE ? TT_COLOR_BLACK : TT_COLOR_WHITE))
                legal = true;
        } else if (dr == 0 && df == -2) { /* queenside castle */
            bool qs = (p.color == TT_COLOR_WHITE) ? g->white_qs : g->black_qs;
            int r = from_rank;
            if (qs && g->board[r][1].type == TT_PIECE_NONE &&
                g->board[r][2].type == TT_PIECE_NONE &&
                g->board[r][3].type == TT_PIECE_NONE &&
                g->board[r][0].type == TT_PIECE_ROOK &&
                g->board[r][0].color == p.color &&
                !tt_chess_square_attacked(g, r, 4, p.color == TT_COLOR_WHITE ? TT_COLOR_BLACK : TT_COLOR_WHITE) &&
                !tt_chess_square_attacked(g, r, 3, p.color == TT_COLOR_WHITE ? TT_COLOR_BLACK : TT_COLOR_WHITE) &&
                !tt_chess_square_attacked(g, r, 2, p.color == TT_COLOR_WHITE ? TT_COLOR_BLACK : TT_COLOR_WHITE))
                legal = true;
        }
    } else if (p.type == TT_PIECE_ROOK || p.type == TT_PIECE_BISHOP || p.type == TT_PIECE_QUEEN) {
        int step_r = (dr > 0) - (dr < 0);
        int step_f = (df > 0) - (df < 0);
        bool straight = (dr == 0) != (df == 0);
        bool diag = (dr != 0) && (df != 0) && (dr == df || dr == -df);
        bool ok = false;
        if (p.type == TT_PIECE_ROOK && straight) ok = true;
        else if (p.type == TT_PIECE_BISHOP && diag) ok = true;
        else if (p.type == TT_PIECE_QUEEN && (straight || diag)) ok = true;
        if (ok) {
            int r = from_rank + step_r, f = from_file + step_f;
            legal = true;
            while (r != to_rank || f != to_file) {
                if (g->board[r][f].type != TT_PIECE_NONE) { legal = false; break; }
                r += step_r;
                f += step_f;
            }
        }
    }

    if (!legal) return false;

    /* castling: move the rook too */
    if (p.type == TT_PIECE_KING && df == 2) {
        g->board[from_rank][5] = g->board[from_rank][7];
        g->board[from_rank][7].type = TT_PIECE_NONE;
        g->board[from_rank][7].color = TT_COLOR_WHITE;
    } else if (p.type == TT_PIECE_KING && df == -2) {
        g->board[from_rank][3] = g->board[from_rank][0];
        g->board[from_rank][0].type = TT_PIECE_NONE;
        g->board[from_rank][0].color = TT_COLOR_WHITE;
    }

    /* en passant capture: remove the pawn behind */
    if (p.type == TT_PIECE_PAWN && df != 0 && t.type == TT_PIECE_NONE) {
        g->board[from_rank][to_file].type = TT_PIECE_NONE;
        g->board[from_rank][to_file].color = TT_COLOR_WHITE;
    }

    /* record en-passant target for a double pawn push */
    g->ep_file = -1;
    if (p.type == TT_PIECE_PAWN && dr == 2 * (p.color == TT_COLOR_WHITE ? 1 : -1))
        g->ep_file = from_file;

    /* move the piece; auto-promote to queen (toxic has no promotion byte) */
    g->board[to_rank][to_file] = p;
    if (p.type == TT_PIECE_PAWN && (to_rank == 0 || to_rank == 7))
        g->board[to_rank][to_file].type = TT_PIECE_QUEEN;
    g->board[from_rank][from_file].type = TT_PIECE_NONE;
    g->board[from_rank][from_file].color = TT_COLOR_WHITE;

    /* update castling rights */
    if (p.type == TT_PIECE_KING) {
        if (p.color == TT_COLOR_WHITE) { g->white_ks = g->white_qs = false; }
        else { g->black_ks = g->black_qs = false; }
    }
    if (p.type == TT_PIECE_ROOK) {
        if (from_rank == 0 && from_file == 0) g->white_qs = false;
        if (from_rank == 0 && from_file == 7) g->white_ks = false;
        if (from_rank == 7 && from_file == 0) g->black_qs = false;
        if (from_rank == 7 && from_file == 7) g->black_ks = false;
    }
    /* capturing a rook removes the opponent's castling right */
    if (t.type == TT_PIECE_ROOK) {
        if (to_rank == 0 && to_file == 0) g->white_qs = false;
        if (to_rank == 0 && to_file == 7) g->white_ks = false;
        if (to_rank == 7 && to_file == 0) g->black_qs = false;
        if (to_rank == 7 && to_file == 7) g->black_ks = false;
    }

    /* switch side to move */
    g->to_move = (g->to_move == TT_COLOR_WHITE) ? TT_COLOR_BLACK : TT_COLOR_WHITE;

    /* update status */
    TTColor mover = p.color;
    TTColor other = (mover == TT_COLOR_WHITE) ? TT_COLOR_BLACK : TT_COLOR_WHITE;
    if (tt_chess_in_check(g, other)) {
        if (!tt_chess_has_legal_move(g, other)) {
            g->status = TT_CHESS_CHECKMATE;
            g->winner = mover;
        }
    } else if (!tt_chess_has_legal_move(g, other)) {
        g->status = TT_CHESS_STALEMATE;
    }

    return true;
}
